const express = require('express');
const router = express.Router();
const pool = require('../db');
const bcrypt = require('bcrypt'); // 암호화 모듈

// --- 회원가입 페이지 ---
router.get('/register', (req, res) => {
    res.render('register');
});

// [수정됨] 회원가입 처리 (이름, 이메일, 비번확인 추가)
router.post('/register', async (req, res) => {
    try {
        // 1. form에서 5가지 데이터를 받아옴
        const { name, username, email, password, confirm_password } = req.body;

        // 2. 비밀번호 확인 검사
        if (password !== confirm_password) {
            return res.send(`<script>alert('비밀번호가 일치하지 않습니다.'); history.back();</script>`);
        }

        // 3. 비밀번호 암호화 (해싱)
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 4. DB에 저장 (이름, 이메일, 아이디, 암호화된 비번)
        // 주의: DB에 name, email 컬럼이 추가되어 있어야 합니다.
        await pool.query(
            'INSERT INTO users (name, email, username, password) VALUES (?, ?, ?, ?)', 
            [name, email, username, hashedPassword]
        );

        // 5. 가입 성공 시 알림 후 로그인 페이지로 이동
        res.send(`<script>alert('회원가입이 완료되었습니다! 로그인 해주세요.'); location.href='/login';</script>`);

    } catch (err) {
        console.error(err);
        // 아이디나 이메일 중복 시 에러 처리
        res.send(`<script>alert('회원가입 실패! (이미 존재하는 아이디거나 이메일입니다.)'); history.back();</script>`);
    }
});

// --- 로그인 페이지 ---
router.get('/login', (req, res) => {
    res.render('login');
});

// --- 로그인 처리 ---
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const [[user]] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);

        if (user && await bcrypt.compare(password, user.password)) {
            // 로그인 성공: 세션에 유저 정보 저장
            req.session.user = { 
                id: user.id, 
                username: user.username, 
                name: user.name,
                is_admin: user.is_admin 
            };
            
            req.session.save(() => {
                res.redirect('/posts');
            });
        } else {
            res.send(`<script>alert('아이디 또는 비밀번호가 틀립니다.'); history.back();</script>`);
        }
    } catch (err) {
        console.error(err);
        res.status(500).send("로그인 오류");
    }
});

// --- 로그아웃 ---
router.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/posts');
    });
});

// ==========================================
// [관리자] 1. 관리자 페이지 (사용자 목록 조회)
// ==========================================
router.get('/admin', async (req, res) => {
    // 관리자 권한 체크
    if (!req.session.user || req.session.user.is_admin !== 1) {
        return res.send(`<script>alert('관리자만 접근 가능합니다.'); location.href='/posts';</script>`);
    }

    try {
        // 모든 사용자 정보 가져오기 (비밀번호 제외)
        const [users] = await pool.query('SELECT id, name, username, email, is_admin, created_at FROM users ORDER BY id DESC');
        
        res.render('admin', { users }); // users 데이터를 admin.ejs로 보냄
    } catch (err) {
        res.status(500).send("사용자 목록 로드 실패");
    }
});

// ==========================================
// [관리자] 2. 사용자 강제 탈퇴 (삭제)
// ==========================================
router.post('/admin/users/:id/delete', async (req, res) => {
    // 관리자 체크
    if (!req.session.user || req.session.user.is_admin !== 1) {
        return res.status(403).send("권한 없음");
    }

    const targetId = req.params.id;

    // [안전장치] 자기 자신은 삭제 못하게 막기
    if (parseInt(targetId) === req.session.user.id) {
        return res.send(`<script>alert('자기 자신은 삭제할 수 없습니다.'); history.back();</script>`);
    }

    try {
        // 1. 해당 유저가 쓴 게시글 먼저 삭제 (Foreign Key 에러 방지용, 필요시)
        await pool.query('DELETE FROM posts WHERE author_id = ?', [targetId]);
        
        // 2. 유저 삭제
        await pool.query('DELETE FROM users WHERE id = ?', [targetId]);
        
        res.send(`<script>alert('회원이 삭제되었습니다.'); location.href='/admin';</script>`);
    } catch (err) {
        console.error(err);
        res.status(500).send("삭제 중 오류 발생");
    }
});

// ==========================================
// [관리자] 3. 권한 변경 (일반유저 <-> 관리자)
// ==========================================
router.post('/admin/users/:id/role', async (req, res) => {
    if (!req.session.user || req.session.user.is_admin !== 1) return res.status(403).send("권한 없음");

    const targetId = req.params.id;
    const { is_admin } = req.body; // 1이면 관리자, 0이면 일반

    // 자기 자신 권한 해제 방지
    if (parseInt(targetId) === req.session.user.id) {
        return res.send(`<script>alert('자신의 관리자 권한은 해제할 수 없습니다.'); history.back();</script>`);
    }

    try {
        await pool.query('UPDATE users SET is_admin = ? WHERE id = ?', [is_admin, targetId]);
        res.redirect('/admin');
    } catch (err) {
        res.status(500).send("권한 수정 오류");
    }
});

// ==========================================
// [관리자] 4. 회원정보 수정 페이지 보여주기 (GET)
// ==========================================
router.get('/admin/users/:id/edit', async (req, res) => {
    // 1. 관리자 권한 체크
    if (!req.session.user || req.session.user.is_admin !== 1) {
        return res.status(403).send("권한이 없습니다.");
    }

    try {
        const targetId = req.params.id;
        
        // 2. 수정할 회원 정보 가져오기
        const [[user]] = await pool.query("SELECT * FROM users WHERE id = ?", [targetId]);

        if (!user) {
            return res.send(`<script>alert('존재하지 않는 회원입니다.'); history.back();</script>`);
        }

        // 3. 수정 페이지 렌더링
        res.render('admin_user_edit', { targetUser: user });

    } catch (err) {
        res.status(500).send("회원 정보 로드 오류");
    }
});

// ==========================================
// [관리자] 5. 회원정보 수정 저장하기 (POST)
// ==========================================
router.post('/admin/users/:id/update', async (req, res) => {
    // 1. 관리자 권한 체크
    if (!req.session.user || req.session.user.is_admin !== 1) {
        return res.status(403).send("권한이 없습니다.");
    }

    try {
        const targetId = req.params.id;
        const { name, email } = req.body; // form에서 보낸 이름과 이메일 받기

        // 2. DB 업데이트 실행
        await pool.query(
            "UPDATE users SET name = ?, email = ? WHERE id = ?",
            [name, email, targetId]
        );

        // 3. 성공 시 관리자 목록으로 이동
        res.send(`<script>alert('회원 정보가 수정되었습니다.'); location.href='/admin';</script>`);

    } catch (err) {
        console.error(err);
        res.send(`<script>alert('수정 실패! (이메일 중복 등)'); history.back();</script>`);
    }
});

module.exports = router;
module.exports = router;