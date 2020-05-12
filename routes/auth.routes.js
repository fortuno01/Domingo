const { Router } = require("express");
const config = require('config')
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken')
const { check, validationResult } = require("express-validator");
const User = require("../models/User");
const router = Router();

router.post(
  "/register",
  [
    check("email", "Неправильный email").isEmail(),
    check("password", "Некорректный пароль").isLength(),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty) {
        return res.status(400).json({
          errors: errors.array(),
          message: "Некорректные данные",
        });
      }

      const { email, password } = req.body;
      const canditate = await User.findOne({ email });

      if (canditate) {
        return res
          .status(400)
          .json({ message: "Такой пользователь уже зарегистрирован" });
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const user = new User({ email, password: hashedPassword });

      await user.save();

      res.status(201).json({ message: "Пользователь создан" });
    } catch (e) {
      res.status(500).json({ message: "Все пошло не по плану" });
    }
  }
);

router.post(
  "/login",
  [
    check("email", "Введите email").exists(),
    check("password", "Введите пароль").exists(),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty) {
        return res.status(400).json({
          errors: errors.array(),
          message: "Некорректные данные",
        });
      }

      const { email, password } = req.body;
      const user = await User.findOne({ email });
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(400).json({ message: "Неверные данные" });
      }

      const token = jwt.sign(
          {userId: user.id },
          config.get('jwtSecret'),
          {expiresIn: '1h'}
      )

      res.json({token})
    } catch (e) {
      res.status(500).json({ message: "Все пошло не по плану" });
    }
  }
);

module.exports = router;
