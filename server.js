const express = require('express');
const session = require('express-session');
const path = require('path');

const {
  findPasswordByValue,
  incrementUseCount,
  logAccess,
  getAllPasswords,
  addPassword,
  deletePassword,
  updatePasswordStatus,
  updatePasswordTools,
  getAccessLogs
} = require('./database.js');

const app = express();
const PORT = process.env.PORT || 3000;

// 当前工具名称（用于权限检查）
const TOOL_NAME = process.env.TOOL_NAME || 'shaici';

// Session 中间件
app.use(session({
  secret: process.env.SESSION_SECRET || 'shaici-session-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24小时
}));

// 解析 JSON body
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 静态文件
app.use(express.static(path.join(__dirname, 'public')));

// 中间件：检查是否已登录
function requireAuth(req, res, next) {
  if (!req.session.authenticated) {
    return res.redirect('/login');
  }
  next();
}

// ========== 页面路由 ==========

// 登录页
app.get('/login', (req, res) => {
  if (req.session.authenticated) return res.redirect('/tool');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 工具页（需登录）
app.get('/tool', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'tool.html'));
});

// 管理后台（需管理员登录）
app.get('/admin', (req, res) => {
  // 如果未登录管理后台，显示管理登录界面
  if (!req.session.adminAuth) {
    req.session.returnTo = '/admin';
    return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  }
  // 已登录，返回同一个页面（前端会检测session状态展示不同内容）
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 根路径重定向到登录
app.get('/', (req, res) => res.redirect('/login'));

// ========== API 路由 ==========

// 验证口令
app.post('/api/verify', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password || password.trim().length === 0) {
      return res.json({ success: false, message: '请输入口令' });
    }

    const pwd = await findPasswordByValue(password.trim());

    if (!pwd) {
      return res.json({ success: false, message: '口令错误' });
    }

    if (pwd.is_active !== 1) {
      return res.json({ success: false, message: '口令已禁用' });
    }

    // 检查过期
    if (pwd.expires_at && new Date(pwd.expires_at) < new Date()) {
      return res.json({ success: false, message: '口令已过期' });
    }

    // 检查使用次数限制
    if (pwd.max_uses && pwd.used_count >= pwd.max_uses) {
      return res.json({ success: false, message: '口令使用次数已达上限' });
    }

    // 检查工具权限
    if (Array.isArray(pwd.allowed_tools) && !pwd.allowed_tools.includes(TOOL_NAME)) {
      return res.json({ success: false, message: '该口令无权访问此工具' });
    }

    // 增加使用次数
    await incrementUseCount(pwd.id);

    // 记录访问日志
    await logAccess(
      pwd.id,
      req.ip || req.headers['x-forwarded-for'] || 'unknown',
      req.headers['user-agent']
    );

    // 设置登录状态
    req.session.authenticated = true;
    req.session.passwordName = pwd.name;
    req.session.passwordId = pwd.id;

    return res.json({ success: true, name: pwd.name });

  } catch (error) {
    console.error('验证错误:', error);
    return res.status(500).json({ success: false, message: '服务器内部错误' });
  }
});

// 检查登录状态
app.get('/api/check-auth', (req, res) => {
  res.json({
    authenticated: !!req.session.authenticated,
    passwordName: req.session.passwordName || null
  });
});

// 退出登录
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// ========== 管理后台 API ==========

// 管理员验证
app.post('/api/admin/verify', (req, res) => {
  const { password } = req.body;
  if (password === 'admin123') {
    req.session.adminAuth = true;
    return res.json({ success: true });
  }
  return res.json({ success: false, message: '密码错误' });
});

// 管理员退出
app.post('/api/admin/logout', (req, res) => {
  req.session.adminAuth = false;
  res.json({ success: true });
});

// 获取所有口令列表
app.get('/api/admin/passwords', async (req, res) => {
  try {
    const passwords = await getAllPasswords();
    res.json({ success: true, data: passwords });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 添加口令
app.post('/api/admin/passwords', async (req, res) => {
  try {
    const { name, password, expires_at, max_uses } = req.body;
    if (!name || !password) {
      return res.status(400).json({ success: false, message: '名称和口令不能为空' });
    }
    const newPwd = await addPassword(name, password, expires_at || null, max_uses || null);
    res.json({ success: true, data: newPwd });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 删除口令
app.delete('/api/admin/passwords/:id', async (req, res) => {
  try {
    await deletePassword(parseInt(req.params.id));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 更新口令启用/禁用状态
app.put('/api/admin/passwords/:id/status', async (req, res) => {
  try {
    const { is_active } = req.body;
    await updatePasswordStatus(parseInt(req.params.id), is_active === 1 || is_active === true);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 更新口令工具权限
app.put('/api/admin/passwords/:id/tools', async (req, res) => {
  try {
    const { allowed_tools } = req.body;
    // 如果为空数组，设为null表示允许所有工具
    const toolsValue = Array.isArray(allowed_tools) && allowed_tools.length > 0 ? allowed_tools : null;
    await updatePasswordTools(parseInt(req.params.id), toolsValue);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 获取访问日志
app.get('/api/admin/logs', async (req, res) => {
  try {
    const logs = await getAccessLogs(100);
    res.json({ success: true, data: logs });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`=== 筛词神器口令系统 ===`);
  console.log(`端口: ${PORT}`);
  console.log(`工具名: ${TOOL_NAME}`);
  console.log(`登录页: http://localhost:${PORT}/login`);
  console.log(`管理后台: http://localhost:${PORT}/admin`);
});
