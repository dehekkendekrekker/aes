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
localparam CTRL_IDLE  = 3'h0;
localparam CTRL_INIT  = 3'h1;
localparam CTRL_EXPANDING = 3'h2;
localparam CTRL_DECRYPTING  = 3'h3;
localparam CTRL_DONE  = 3'h4;

//----------------------------------------------------------------
// Registers including update variables and write enable.
//----------------------------------------------------------------
reg [2 : 0] module_ctrl_reg;
reg [2 : 0] module_ctrl_new;
reg         module_ctrl_we;

reg         result_valid_reg;
reg         result_valid_new;
reg         result_valid_we;

reg [255 : 0]   key_reg;
reg [255 : 0]   key_new;
reg             key_we;

reg [127 : 0]   iv_reg;
reg [127 : 0]   iv_new;
reg             iv_we;

reg [127 : 0]   block_reg;
reg [127 : 0]   block_new;
reg             block_we;

reg [127 : 0] result_reg;
reg [127 : 0] result_new;
reg           result_we;

reg         ready_reg;
reg         ready_new;
reg         ready_we;

reg         core_init_reg;
reg         core_init_new;
reg         core_init_we;

reg         core_next_reg;
reg         core_next_new;
reg         core_next_we;


//----------------------------------------------------------------
// Wires.
//----------------------------------------------------------------
wire            core_init;
wire            core_next;
wire            core_ready;
wire [127 : 0]  core_result;
wire            core_result_valid;

wire [127 : 0 ] core_iv;
wire [127 : 0 ] core_block;
wire [255 : 0 ] core_key;


//----------------------------------------------------------------
// Concurrent connectivity for ports etc.
//----------------------------------------------------------------
assign ready        = ready_reg;
assign result       = result_reg;
assign result_valid = result_valid_reg;
assign core_init = core_init_reg;
assign core_next = core_next_reg;

assign core_block = block_reg;
assign core_key   = key_reg;
assign core_iv    = iv_reg;



//----------------------------------------------------------------
// Instantiations.
//----------------------------------------------------------------
aes_core aes_core_inst(
    .clk(clk),
    .reset_n(reset_n),
    .init(core_init),
    .next(core_next),
    .ready(core_ready),
    .key(core_key),
    .block(core_block),
    .result(core_result),
    .result_valid(core_result_valid)
);


//----------------------------------------------------------------
// reg_update
//
// Update functionality for all registers in the core.
// All registers are positive edge triggered with asynchronous
// active low reset. All registers have write enable.
//----------------------------------------------------------------
always @ (posedge clk or negedge reset_n)
begin: reg_update
    if (!reset_n)
    begin
        result_valid_reg  <= 1'b0;
        ready_reg         <= 1'b1;
        core_init_reg     <= 1'b0;
        core_next_reg     <= 1'b0;
        result_reg        <= 128'b0;
        key_reg           <= 256'b0;
        iv_reg            <= 128'b0;
        block_reg         <= 128'b0;
        module_ctrl_reg   <= CTRL_IDLE;
    end
    else
    begin
        if (result_valid_we)
            result_valid_reg <= result_valid_new;

        if (ready_we)
            ready_reg <= ready_new;

        if (module_ctrl_we)
            module_ctrl_reg <= module_ctrl_new;

        if (core_init_we)
            core_init_reg <= core_init_new;

        if (core_next_we)
            core_next_reg <= core_next_new;

        if (result_we)
            result_reg <= result_new;

        if (key_we)
            key_reg <= key_new;

        if (iv_we)
            iv_reg <= iv_new;

        if (block_we)
            block_reg <= block_new;
    end
end // reg_update

//----------------------------------------------------------------
// aes_256_cbc_ctrl
//
// Control FSM for aes module. 
//----------------------------------------------------------------
always @* begin : main_fsm
    result_valid_new =  1'b0;
    result_valid_we  =  1'b0;

    result_new = 128'b0;
    result_we  = 1'b0;

    ready_new = 1'b0;
    ready_we = 1'b0;

    core_init_new = 1'b0;
    core_init_we = 1'b0;

    core_next_new = 1'b0;
    core_next_we = 1'b0;

    block_new = 0;
    block_we  = 0;

    key_new = 0;
    key_we  = 0;

    iv_new  =   0;
    iv_we   =   0;

    module_ctrl_new = CTRL_IDLE;
    module_ctrl_we  = 1'b0;
    

    case (module_ctrl_reg)
    CTRL_IDLE: begin
        if (init) begin
            ready_new         = 1'b0;
            ready_we          = 1'b1;
            result_valid_new  = 1'b0;
            result_valid_we   = 1'b1;
            core_init_new     = 1'b1;
            core_init_we      = 1'b1;
            module_ctrl_new   = CTRL_INIT;
            module_ctrl_we    = 1'b1;

            key_new     = key;
            key_we      = 1;
            iv_new      = iv;
            iv_we       = 1;
            block_new   = block;
            block_we    = 1;

            
        end
    end

    CTRL_INIT: begin
        core_init_new     = 1'b0;
        core_init_we      = 1'b1;
        module_ctrl_new   = CTRL_EXPANDING;
        module_ctrl_we    = 1'b1;
    end

    CTRL_EXPANDING: begin
        core_init_new = 1'b0;
        core_init_we  = 1'b1;
        if (core_ready) begin
            core_next_new     = 1'b1;
            core_next_we      = 1'b1;
            module_ctrl_new   = CTRL_DECRYPTING;
            module_ctrl_we    = 1'b1;
        end
    end

    CTRL_DECRYPTING: begin
        core_next_new = 1'b0;
        core_next_we  = 1'b1;
        if(core_result_valid) begin
            core_next_new = 0;
            core_next_we = 1;
            module_ctrl_new   = CTRL_DONE;
            module_ctrl_we    = 1'b1;
        end
    end

    CTRL_DONE: begin
        result_new = core_result ^ core_iv;
        result_we   = 1'b1;
        module_ctrl_new   = CTRL_IDLE;
        module_ctrl_we    = 1'b1;

        ready_new = 1'b1;
        ready_we  = 1'b1;
        result_valid_new = 1'b1;
        result_valid_we  = 1'b1;
    end
    endcase
end

endmodule