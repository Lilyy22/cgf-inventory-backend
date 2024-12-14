import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<string[]>(
      'roles', // use 'roles' instead of 'role' to match what the @Roles decorator sets
      context.getHandler(),
    );

    if (!requiredRoles) {
      return true; // No roles required, allow access
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user; // Get the authenticated user

    console.log('No role found for this user', user, user.role);
    if (!user || !user.role) {
      throw new ForbiddenException('No role found for this user');
    }

    // Check if the user's role matches the required roles
    const hasRole = requiredRoles.includes(user.role);

    if (!hasRole) {
      console.log('You do not have the necessary roles');
      throw new ForbiddenException('You do not have the necessary roles');
    }

    return true;
  }
}
