package server

import (
	"database/sql"
	"errors"

	"github.com/Autumn-27/artex/agent"
)

// seedModelerAgent seeds the built-in `modeler` (业务建模) agent atomically, mirroring
// seedFindingRetester (Pattern B): transaction + advisory lock + settings flag, with
// an `INSERT ... ON CONFLICT (key) DO NOTHING` so a user-created key or prior seed is
// kept, and the prompt inserted as version 1 with current_prompt_id set.
//
// The modeler's function-graph tools are seeded separately through the ordinary
// BuiltinToolSeeds()/wireTools path (toolcatalog.go now binds them to "modeler"), so
// this function only creates the agent row + prompt. role must be 'assistant'
// (schema.sql agents_role_ck allows only goals/main/planner/worker/assistant);
// builtin=false so users can edit or delete it, like reporter/retester.
func (s *Server) seedModelerAgent() error {
	const flag = "modeler_seed_v1"
	tx, err := s.m.pg.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(7337741010)`); err != nil {
		return err
	}
	var done string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=$1`, flag).Scan(&done)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if done == "true" {
		return nil
	}
	var id int64
	err = tx.QueryRow(`INSERT INTO agents(key,name,description,role,builtin,enabled)
	VALUES ('modeler','业务建模','任务开局按角色重建站点业务功能图(模块/功能/动作+角色可达性+不变量),只建模不攻击,供规划者系统性派越权/逻辑测试意图。','assistant',false,true)
	ON CONFLICT (key) DO NOTHING RETURNING id`).Scan(&id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if id > 0 {
		var pid int64
		if err = tx.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by)
		VALUES ($1,1,$2,'内置默认','system') RETURNING id`, id, agent.ModelerDefaultPrompt).Scan(&pid); err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE agents SET current_prompt_id=$1 WHERE id=$2`, pid, id); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`INSERT INTO settings(key,value) VALUES ($1,'true') ON CONFLICT(key) DO UPDATE SET value='true'`, flag); err != nil {
		return err
	}
	return tx.Commit()
}
