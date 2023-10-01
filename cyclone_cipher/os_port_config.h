/**
 * @file os_port_config.h
 * @brief RTOS port configuration file
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2023 Oryx Embedded SARL. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.4
 **/

#ifndef _OS_PORT_CONFIG_H
#define _OS_PORT_CONFIG_H
typedef unsigned long size_t;

int myosTolower(int c);
int myosToupper(int c);
int myosIsupper(int c);
int myosIsdigit(int c);
int myosIsspace(int c);
void myosMemcpy(void *dest, const void *src, size_t n);
void* myosMemset(void *s, int c, size_t n);
void myosMemmove(void *dest, void *src, size_t n);
int myosMemcmp(void* ptr1, void* ptr2, size_t num);
void* myosMemchr(const void* ptr, char c, size_t n);
size_t myosStrlen(const char* s);
int myosStrcmp(const char* str1, const char* str2);
int myosStrncmp(const char* str1, const char* str2, size_t n);
int myosStrcasecmp(const char* s1, const char* s2);
int myosStrncasecmp(const char* s1, const char* s2, size_t n);
char* myosStrchr(const char* str, char c);
char* myosStrstr(const char* haystack, const char* needle);
char* myosStrcpy(char* dest, const char* src);
char* myosStrncpy(char* dest, const char* src, size_t n);
char* myosStrcat(char* s1, const char* s2);


#endif
