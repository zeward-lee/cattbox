// 本文件由上游 v1.20.2 的 transport/anytls/session/patch.go 裁剪而来，仅保留 CloseIdle；
// 上游那个依赖 once 字段做惰性初始化的清理启动方法已删除（本地 Client 结构体无该字段），
// 即时初始化职责由本地 session/client.go 的 NewClient 承担。
package session

func (c *Client) CloseIdle() {
	c.idleSessionLock.Lock()
	if c.idleSession == nil || c.idleSession.IsEmpty() {
		c.idleSessionLock.Unlock()
		return
	}
	sessionToClose := make([]*Session, 0, c.idleSession.Len())
	c.idleSession.ForEach(func(_ uint64, session *Session) {
		sessionToClose = append(sessionToClose, session)
	})
	c.idleSession.Clear()
	c.idleSessionLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}
}
