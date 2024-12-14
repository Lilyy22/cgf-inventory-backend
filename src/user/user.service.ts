// src/user/user.service.ts

import { ForbiddenException, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from 'prisma/prisma.service';
import { CreateUserDto } from './dto/CreateUserDto.dto';

@Injectable()
export class UserService {
  constructor(private readonly prismaService: PrismaService) {}

  // Register a new user with hashed password
  async register(createUserDto: CreateUserDto) {
    // Check if the email is already in use
    const existingUser = await this.findUserByEmail(createUserDto.email);

    if (existingUser) {
      throw new Error('Email is already in use'); // Handle with proper exception in production
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    // get user role and assign it to register
    const userRole = await this.prismaService.role.findUnique({
      where: { name: 'User' },
    });

    // Create the new user
    const newUser = await this.prismaService.user.create({
      data: {
        email: createUserDto.email,
        role_id: userRole.id,
        password: hashedPassword,
      },
    });

    return newUser;
  }

  async findUserByEmail(email: string) {
    try {
      const user = await this.prismaService.user.findUnique({
        where: { email: email },
        include: {
          role: true, // Include role details (name) in the query
        },
      });

      return user;
    } catch (err) {
      throw new ForbiddenException(err);
    }
  }

  // Find a user by username
  // async findByUsername(username: string) {
  //   return this.prismaService.user.find((user) => user.username === username); // Replace with actual DB logic
  // }
}
