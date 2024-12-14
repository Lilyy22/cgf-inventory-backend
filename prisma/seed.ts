import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  // Define roles
  const roles = [{ name: 'Admin' }, { name: 'Manager' }, { name: 'User' }];

  // Define permissions
  const permissions = [
    { action: 'user:read', name: 'Read Users', resource: 'user' },
    { action: 'user:create', name: 'Create Users', resource: 'user' },
    { action: 'user:update', name: 'Update Users', resource: 'user' },
    { action: 'user:delete', name: 'Delete Users', resource: 'user' },
  ];

  // Seed roles
  for (const role of roles) {
    await prisma.role.create({
      data: role,
    });
  }

  // Seed permissions
  for (const permission of permissions) {
    await prisma.permission.create({
      data: permission,
    });
  }
  const adminRole = await prisma.role.findUnique({ where: { name: 'Admin' } });

  // Assign permissions to roles (Admin gets all permissions)
  if (adminRole) {
    const allPermission = await prisma.permission.findMany();
    for (const permission of allPermission) {
      await prisma.rolePermission.create({
        data: {
          role_id: adminRole.id,
          permission_id: permission.id,
        },
      });
    }
  }

  // Seed Admin user
  await prisma.user.create({
    data: {
      //   email: 'Johnnie Yu',
      role_id: adminRole.id,
      email: 'johnnieyu@pragmaticdlt.com',
      password: '$2b$10$mfDRmPnfcX0IeS2H2OWXjel797969HBp3oFoj50cYX9oA6RjV7Zrq', //Bk7aT61OkpdJDiA
    },
  });

  console.log('Seeding complete');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
