// src/auth/auth.service.ts

import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UserService } from '../user/user.service'; // Assuming you have a UserService
import { LoginUserDto } from './dto/LoginUserDto.dto';
import { Response } from 'express';
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private userService: UserService, // Inject UserService to validate users
    private prismaService: PrismaService, // Inject UserService to validate users
  ) {}

  // Validate user credentials (username and password)
  async validateUser(email: string, password: string) {
    const user = await this.userService.findUserByEmail(email);
    if (user && bcrypt.compareSync(password, user.password)) {
      return user; // Return user if valid
    }
    throw new UnauthorizedException('Invalid credentials');
    // return null; // Return null if invalid
  }

  // Sign JWT token and return it
  async login(loginUserDto: LoginUserDto, res: Response) {
    const user = await this.userService.findUserByEmail(loginUserDto.email);
    const payload = {
      role: user.role.name,
      sub: user.id,
    };

    return this.tokens(payload, res);
  }

  // logout clear http cookie
  async logout(res: Response) {
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
    });

    return res.json({ message: 'Logged out successfully' });
  }

  async refreshToken(req, res) {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }

    // Retrieve the hashed refresh token from the database
    const tokenEntry = await this.getRefreshToken(req.user.id);

    if (!tokenEntry) {
      throw new UnauthorizedException('No token entry found');
    }

    // Compare the hashed token with the token from the cookie
    const isMatch = await bcrypt.compare(refreshToken, tokenEntry.refreshToken);

    if (!isMatch) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    try {
      const payload = this.jwtService.verify(refreshToken);
      return this.tokens(payload, res);
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  // Validate JWT token user
  async tokens(payload, res) {
    const refresh_token = this.jwtService.sign(payload, {
      expiresIn: '7d', // Refresh token expiration (e.g., 7 days)
    });

    res.cookie('refreshToken', refresh_token, {
      httpOnly: true,
      secure: true, // Use only with HTTPS
      sameSite: 'strict', // Mitigate CSRF
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Explicitly return a JSON response
    return res
      .status(200)
      .json({ access_token: this.jwtService.sign(payload) });
  }

  // Validate JWT token user
  async validateJwtUser(payload: any) {
    return { userId: payload.sub, username: payload.username };
  }

  async insertRefreshToken(userId, token) {
    try {
      const hashedToken = await bcrypt.hash(token, 10);
      return await this.prismaService.refreshTokens.create({
        data: {
          user_id: userId,
          refreshToken: hashedToken,
        },
      });
    } catch (err) {
      return err;
    }
  }

  async getRefreshToken(userId) {
    try {
      return await this.prismaService.refreshTokens.findOne({
        where: {
          user_id: userId,
        },
      });
    } catch (err) {
      return err;
    }
  }
}
