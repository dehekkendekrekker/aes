//======================================================================
//
// aes_core.v
// ----------
// The AES core. This core supports key size of 128, and 256 bits.
// Most of the functionality is within the submodules.
//
//
// Author: DHK
// Copyright (c) 2023, Rawatech R&D
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================
module aes_256_cbc (
        input wire clk,
        input wire reset_n,

        input wire            init,
        output wire           ready,

        input wire [255 : 0]  key,
        input wire [127 : 0]  iv,
        input wire [127 : 0]  block,

        output wire [127 : 0] result,
        output wire           result_valid
);



//----------------------------------------------------------------
// Internal constant and parameter definitions.
//----------------------------------------------------------------
localparam CTRL_IDLE  = 2'h0;
localparam CTRL_INIT  = 2'h1;
localparam CTRL_DECRYPTING  = 2'h2;
localparam CTRL_DONE  = 2'h3;



//----------------------------------------------------------------
// aes_256_cbc_ctrl
//
// Control FSM for aes mopdule. 
//----------------------------------------------------------------


endmodule