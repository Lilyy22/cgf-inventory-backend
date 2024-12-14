// src/auth/local.strategy.ts

import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from './auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email', // Use email as username
      passwordField: 'password', // Use password field as password
    });
  }

  async validate(email: string, password: string) {
    return this.authService.validateUser(email, password);
  }
}
