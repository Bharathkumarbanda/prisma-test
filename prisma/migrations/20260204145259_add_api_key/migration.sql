/*
  Warnings:

  - Added the required column `api_key` to the `users` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "users" ADD COLUMN     "api_key" TEXT NOT NULL;
