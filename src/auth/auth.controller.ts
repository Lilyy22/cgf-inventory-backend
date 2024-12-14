// src/auth/auth.controller.ts

import { Controller, Post, Body, UseGuards, Res, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { LoginUserDto } from './dto/LoginUserDto.dto';
import { Request, Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  // User login
  @Post('login')
  @UseGuards(LocalAuthGuard) // Protect login route with local strategy
  async login(@Body() loginUserDto: LoginUserDto, @Res() res: Response) {
    return this.authService.login(loginUserDto, res); // Generate JWT token
  }

  // User login
  @Post('refresh')
  @UseGuards(LocalAuthGuard) // Protect login route with local strategy
  async refreshToken(@Req() req: Request, @Res() res: Response) {
    return this.authService.refreshToken(req, res); // Generate JWT token
  }

  // User logout
  @Post('logout')
  async logout(@Res() res: Response) {
    return this.authService.logout(res);
  }
}
