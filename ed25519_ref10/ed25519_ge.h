/*************************************************************************/
/*  ed25519_ge.h                                                         */
/*************************************************************************/
/*                     This file is part of the                          */
/*             Maria and Mysql database connection module                */
/*                    for use in the Godot Engine                        */
/*                           GODOT ENGINE                                */
/*                      https://godotengine.org                          */
/* This file was derived from information found at                       */
/* https://tools.ietf.org/html/rfc8032#page-44                           */
/*************************************************************************/
/* Copyright (c) 2021 Shawn Shipton. https://vikingtinkerer.com          */
/*                                                                       */
/* Permission is hereby granted, free of charge, to any person obtaining */
/* a copy of this software and associated documentation files (the       */
/* "Software"), to deal in the Software without restriction, including   */
/* without limitation the rights to use, copy, modify, merge, publish,   */
/* distribute, sublicense, and/or sell copies of the Software, and to    */
/* permit persons to whom the Software is furnished to do so, subject to */
/* the following conditions:                                             */
/*                                                                       */
/* The above copyright notice and this permission notice shall be        */
/* included in all copies or substantial portions of the Software.       */
/*                                                                       */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,       */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF    */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.*/
/* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY  */
/* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,  */
/* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE     */
/* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                */
/*************************************************************************/

#ifndef ED25519_GE_H
#define ED25519_GE_H

#include "ed25519_fe.h"

/*
ge means group element.

Here the group is the set of pairs (x,y) of field elements (see fe.h)
satisfying -x^2 + y^2 = 1 + d x^2y^2
where d = -121665/121666.

Representations:
  ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
  ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
  ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
  ge_precomp (Duif): (y+x,y-x,2dxy)
*/

typedef struct {
	fe X;
	fe Y;
	fe Z;
} ge_p2;

typedef struct {
	fe X;
	fe Y;
	fe Z;
	fe T;
} ge_p3;

typedef struct {
	fe X;
	fe Y;
	fe Z;
	fe T;
} ge_p1p1;

typedef struct {
	fe yplusx;
	fe yminusx;
	fe xy2d;
} ge_precomp;

typedef struct {
	fe YplusX;
	fe YminusX;
	fe Z;
	fe T2d;
} ge_cached;

void ge_p3_tobytes(uint8_t *s, const ge_p3 *h);
void ge_tobytes(uint8_t *s, const ge_p2 *h);
int ge_frombytes_negate_vartime(ge_p3 *h, const uint8_t *s);

void ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void ge_double_scalarmult_vartime(ge_p2 *r, const uint8_t *a, const ge_p3 *A, const uint8_t *b);
void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q);
void ge_msub(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q);
void ge_scalarmult_base(ge_p3 *h, const uint8_t *a);

void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p);
void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p);
void ge_p2_0(ge_p2 *h);
void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p);
void ge_p3_0(ge_p3 *h);
void ge_p3_dbl(ge_p1p1 *r, const ge_p3 *p);
void ge_p3_to_cached(ge_cached *r, const ge_p3 *p);
void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p);

#endif // !ED25519_GE_H
