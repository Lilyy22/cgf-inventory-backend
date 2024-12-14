import { Controller, Post, Body, Get, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/CreateUserDto.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { Roles } from 'src/auth/decorators/role.decorator';
import { RolesGuard } from 'src/auth/guards/role.guard';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  // Endpoint to register a user
  // @Post('register')
  // async register(@Body() body: { username: string; password: string }) {
  //   return this.userService.register(body.username, body.password);
  // }

  @Post('signup')
  async register(@Body() createUserDto: CreateUserDto) {
    // Access validated `createUserDto` here
    return this.userService.register(createUserDto);
  }

  @Get('get')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin', 'User')
  async findUser(@Body() emailObj: any) {
    return this.userService.findUserByEmail(emailObj.email);
  }
}
