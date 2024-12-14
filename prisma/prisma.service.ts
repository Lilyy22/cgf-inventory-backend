import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  // Called when the module initializes
  async onModuleInit() {
    await this.$connect();
    console.log('Prisma connected to the database');
  }

  // Called when the module is destroyed
  async onModuleDestroy() {
    await this.$disconnect();
    console.log('Prisma disconnected from the database');
  }

  // Optional: If using NestJS lifecycle hooks (e.g., app shutdown)
  // async enableShutdownHooks(app: any) {
  //   this.$on('beforeExit', async () => {
  //     await app.close();
  //   });
  // }
}
