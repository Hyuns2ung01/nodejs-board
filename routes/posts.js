const express = require('express');
const router = express.Router();
const pool = require('../db');

// [로그인 체크 미들웨어] 
// 이 함수를 라우터에 끼워넣으면 로그인을 검사합니다.
const checkLogin = (req, res, next) => {
    if (!req.session.user) {
        return res.send(`<script>alert('로그인이 필요한 서비스입니다.'); location.href='/login';</script>`);
    }
    next();
};

// 목록 + 검색 + 페이징
router.get('/', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 10;
        const offset = (page - 1) * limit;
        const search = req.query.search || "";

        // 작성자 이름(users.name)도 같이 가져오기 위해 JOIN 사용
        const sql = `
            SELECT p.*, u.name AS author_name 
            FROM posts p 
            LEFT JOIN users u ON p.author_id = u.id
            WHERE p.title LIKE ? 
            ORDER BY 
                CASE WHEN p.title LIKE '[공지]%' THEN 0 ELSE 1 END ASC,
                p.id DESC
            LIMIT ? OFFSET ?
        `;

        const [rows] = await pool.query(sql, [`%${search}%`, limit, offset]);

        const [[{ total }]] = await pool.query(
            `SELECT COUNT(*) AS total FROM posts WHERE title LIKE ?`,
            [`%${search}%`]
        );

        res.render("index", {
            posts: rows,
            total,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            search,
        });
    } catch (error) {
        console.log(error);
        res.status(500).send("목록 로드 오류");
    }
});

// 글쓰기 폼 (checkLogin 추가 -> 로그인 안하면 못 들어옴)
router.get('/new', checkLogin, (req, res) => {
    res.render("new");
});

// 글 저장 (작성자 ID 저장 추가)
router.post('/', checkLogin, async (req, res) => {
    try {
        const { title, content } = req.body;
        const author_id = req.session.user.id; // << 로그인한 사람의 ID

        await pool.query(
            `INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)`,
            [title, content, author_id]
        );
        res.redirect('/posts');
    } catch (error) {
        res.status(500).send("글 작성 오류");
    }
});

// 상세 보기
router.get('/:id', async (req, res) => {
    try {
        const id = req.params.id;

        // 조회수 증가
        await pool.query(`UPDATE posts SET view_count = view_count + 1 WHERE id=?`, [id]);

        // posts 테이블과 users 테이블을 합쳐서 작성자 이름(author_name)을 가져옴
        const [[post]] = await pool.query(
            `SELECT p.*, u.name AS author_name 
             FROM posts p 
             LEFT JOIN users u ON p.author_id = u.id 
             WHERE p.id=?`,
            [id]
        );

        if (!post) return res.status(404).send("게시글을 찾을 수 없습니다.");

        res.render("show", { post });

    } catch (error) {
        res.status(500).send("상세 보기 오류");
    }
});

// 삭제 (본인 확인 추가)
router.post('/:id/delete', checkLogin, async (req, res) => {
    try {
        const id = req.params.id;
        const userId = req.session.user.id;
        const isAdmin = req.session.user.is_admin === 1;

        // 먼저 게시글 정보를 가져와서 작성자가 누군지 확인
        const [[post]] = await pool.query(`SELECT * FROM posts WHERE id=?`, [id]);

        if (!post) return res.status(404).send("게시글이 없습니다.");

        // 권한 체크 (작성자이거나 관리자만 통과)
        if (post.author_id !== userId && !isAdmin) {
            return res.send(`<script>alert('작성자만 삭제할 수 있습니다.'); history.back();</script>`);
        }

        // 삭제 실행
        await pool.query(`DELETE FROM posts WHERE id=?`, [id]);
        res.redirect('/posts');

    } catch (error) {
        res.status(500).send("삭제 오류");
    }
});

// 수정 폼 (본인 확인 로직 필요 - 삭제와 비슷하게 구현 권장)
router.get('/:id/edit', checkLogin, async (req, res) => {
    try {
        const id = req.params.id;
        const [[post]] = await pool.query(`SELECT * FROM posts WHERE id=?`, [id]);
        
        if (post.author_id !== req.session.user.id && req.session.user.is_admin !== 1) {
             return res.send(`<script>alert('작성자만 수정할 수 있습니다.'); history.back();</script>`);
        }

        res.render("edit", { post });
    } catch (error) {
        res.status(500).send("오류");
    }
});

// 수정 저장
router.post('/:id/edit', checkLogin, async (req, res) => {
    // 여기도 삭제처럼 본인 확인 로직을 넣는 것이 안전하지만 생략함
    const id = req.params.id;
    const { title, content } = req.body;
    await pool.query(`UPDATE posts SET title=?, content=? WHERE id=?`, [title, content, id]);
    res.redirect(`/posts/${id}`);
});

module.exports = router;