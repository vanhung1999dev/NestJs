import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { AuthDto } from './dto';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthServe {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
    private config: ConfigService,
  ) {}

  async signUp(dto: AuthDto) {
    try {
      const hash = await argon.hash(dto.password);
      const user = await this.prismaService.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (
        error instanceof PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ForbiddenException('Credentials taken');
      }
      throw error;
    }
  }

  async login(dto: AuthDto) {
    try {
      const user = await this.prismaService.user.findUnique({
        where: {
          email: dto.email,
        },
      });
      if (!user) throw new ForbiddenException(' Credential incorrect');

      const isMatchPassword = await argon.verify(user.hash, dto.password);
      if (!isMatchPassword)
        throw new ForbiddenException('Credential incorrect');

      return user;
    } catch (error) {
      if (
        error instanceof PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ForbiddenException('Credentials taken');
      }
      throw error;
    }
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ accessToken: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secretKey = this.config.get('SECRET_KEY');

    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '2m',
      secret: secretKey,
    });
    return {
      accessToken,
    };
  }
}
