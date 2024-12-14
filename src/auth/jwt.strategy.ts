// src/auth/jwt.strategy.ts

import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from './auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // Extract token from Authorization header
      secretOrKey: process.env.JWT_SECRET || 'secret', // The JWT secret
    });
  }

  async validate(payload: any) {
    const user = await this.authService.validateJwtUser(payload);

    // Attach the role and other user info to the user object
    return {
      userId: payload.id, // Or however you get the user ID
      username: payload.email, // Or however you get the username
      role: payload.role, // Attach the role from the JWT payload
    };
  }
}
