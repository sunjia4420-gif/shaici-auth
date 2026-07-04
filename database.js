const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = 'https://wgjhijtfhqtkdgddtcwh.supabase.co';
const supabaseKey = 'sb_publishable_4JkQtzY24ldcGfE7BcZs0Q_hdN1Ms-e';
const supabase = createClient(supabaseUrl, supabaseKey);

// 查找口令
async function findPasswordByValue(password) {
  const { data, error } = await supabase
    .from('passwords')
    .select('id,name,password,is_active,expires_at,max_uses,used_count,allowed_tools')
    .eq('password', password)
    .maybeSingle();
  
  if (error) throw error;
  return data;
}

// 增加使用次数
async function incrementUseCount(id) {
  const { error } = await supabase
    .rpc('increment_use_count', { pwd_id: id });
  if (error) console.error('增加使用次数失败:', error.message);
}

// 记录访问日志
async function logAccess(passwordId, ipAddress, userAgent) {
  const { error } = await supabase
    .from('access_logs')
    .insert({
      password_id: passwordId,
      ip_address: ipAddress,
      user_agent: userAgent?.substring(0, 500),
      tool_name: process.env.TOOL_NAME || 'shaici'
    });
  if (error) console.error('记录访问日志失败:', error.message);
}

// 获取所有口令（管理用）
async function getAllPasswords() {
  const { data, error } = await supabase
    .from('passwords')
    .select('*')
    .order('id', { ascending: true });
  if (error) throw error;
  return data || [];
}

// 添加口令（管理用）
async function addPassword(name, password, expiresAt, maxUses) {
  const { data, error } = await supabase
    .from('passwords')
    .insert({ name, password, expires_at: expiresAt, max_uses: maxUses, is_active: 1 })
    .select()
    .single();
  if (error) throw error;
  return data;
}

// 删除口令（管理用）
async function deletePassword(id) {
  const { error } = await supabase
    .from('passwords')
    .delete()
    .eq('id', id);
  if (error) throw error;
}

// 更新口令状态（管理用）
async function updatePasswordStatus(id, isActive) {
  const { error } = await supabase
    .from('passwords')
    .update({ is_active: isActive ? 1 : 0 })
    .eq('id', id);
  if (error) throw error;
}

// 更新口令工具权限（管理用）
async function updatePasswordTools(id, allowedTools) {
  const { error } = await supabase
    .from('passwords')
    .update({ allowed_tools: allowedTools })
    .eq('id', id);
  if (error) throw error;
}

// 获取访问日志（管理用）
async function getAccessLogs(limit = 50) {
  const { data, error } = await supabase
    .from('access_logs')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) throw error;
  return data || [];
}

module.exports = {
  findPasswordByValue,
  incrementUseCount,
  logAccess,
  getAllPasswords,
  addPassword,
  deletePassword,
  updatePasswordStatus,
  updatePasswordTools,
  getAccessLogs
};
