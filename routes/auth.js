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

// --- 관리자 페이지 (미들웨어로 보호) ---
router.get('/admin', (req, res) => {
    // 관리자인지 체크 (is_admin이 1이어야 함)
    if (!req.session.user || req.session.user.is_admin !== 1) {
        return res.send(`<script>alert('관리자 권한이 없습니다.'); location.href='/posts';</script>`);
    }
    res.render('admin');
});

module.exports = router;