/*
*  Copyright (C) 2016 Cisco Talos Security Intelligence and Research Group
*
*  Authors: Matthew Molyett
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License version 2 as
*  published by the Free Software Foundation.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
*  MA 02110-1301, USA.
*
*	Filename: strings.h
*	Last revision: 10/12/2016
*/
#pragma once
#ifndef _LOCKY_DUMP_STRINGS_H
#define _LOCKY_DUMP_STRINGS_H
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

char *stristr(const char *str, const char *strSearch);
wchar_t *wcsistr(const wchar_t *str, const wchar_t *strSearch);

#endif // _LOCKY_DUMP_STRINGS_H