//======================================================================
//
// tb_aes_256_cbc.v
// -------------
// Testbench for the AES block cipher core.
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

`default_nettype none

module tb_aes_256_cbc();

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter DEBUG     = 0;
  parameter DUMP_WAIT = 0;

  parameter CLK_HALF_PERIOD = 1;
  parameter CLK_PERIOD = 2 * CLK_HALF_PERIOD;

  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  reg [31 : 0] cycle_ctr;
  reg [31 : 0] error_ctr;
  reg [31 : 0] tc_ctr;

  reg            tb_clk;
  reg            tb_reset_n;
  reg            tb_init;
  wire           tb_ready;
  reg [255 : 0]  tb_key;
  reg [127 : 0]  tb_iv;
  reg [127 : 0]  tb_block;
  wire [127 : 0] tb_result;
  wire           tb_result_valid;


  //----------------------------------------------------------------
  // Device Under Test.
  //----------------------------------------------------------------
  aes_256_cbc dut(
               .clk(tb_clk),
               .reset_n(tb_reset_n),

               .init(tb_init),

               .key(tb_key),
               .iv(tb_iv),
               .block(tb_block),
               
               .ready(tb_ready),
               .result(tb_result)
              );


  //----------------------------------------------------------------
  // clk_gen
  //
  // Always running clock generator process.
  //----------------------------------------------------------------
  always
    begin : clk_gen
      #CLK_HALF_PERIOD;
      tb_clk = !tb_clk;
    end // clk_gen


  //----------------------------------------------------------------
  // sys_monitor()
  //
  // An always running process that creates a cycle counter and
  // conditionally displays information about the DUT.
  //----------------------------------------------------------------
  always
    begin : sys_monitor
      cycle_ctr = cycle_ctr + 1;
      #(CLK_PERIOD);
      if (DEBUG)
        begin
          dump_dut_state();
        end
    end


  //----------------------------------------------------------------
  // dump_dut_state()
  //
  // Dump the state of the dump when needed.
  //----------------------------------------------------------------
  task dump_dut_state;
    begin
      $display("State of DUT");
      $display("------------");
      $display("Inputs and outputs:");
      $display("init   = 0x%01x, next = 0x%01x", dut.init, dut.next);
      $display("key  = 0x%032x ",dut.key);
      $display("block  = 0x%032x", dut.block);
      $display("");
      $display("ready        = 0x%01x", dut.ready);
      $display("result_valid = 0x%01x, result = 0x%032x",
               dut.result_valid, dut.result);
      $display("");
      $display("");
    end
  endtask // dump_dut_state


  //----------------------------------------------------------------
  // dump_keys()
  //
  // Dump the keys in the key memory of the dut.
  //----------------------------------------------------------------
  task dump_keys;
    begin
      $display("State of key memory in DUT:");
      $display("key[00] = 0x%016x", dut.keymem.key_mem[00]);
      $display("key[01] = 0x%016x", dut.keymem.key_mem[01]);
      $display("key[02] = 0x%016x", dut.keymem.key_mem[02]);
      $display("key[03] = 0x%016x", dut.keymem.key_mem[03]);
      $display("key[04] = 0x%016x", dut.keymem.key_mem[04]);
      $display("key[05] = 0x%016x", dut.keymem.key_mem[05]);
      $display("key[06] = 0x%016x", dut.keymem.key_mem[06]);
      $display("key[07] = 0x%016x", dut.keymem.key_mem[07]);
      $display("key[08] = 0x%016x", dut.keymem.key_mem[08]);
      $display("key[09] = 0x%016x", dut.keymem.key_mem[09]);
      $display("key[10] = 0x%016x", dut.keymem.key_mem[10]);
      $display("key[11] = 0x%016x", dut.keymem.key_mem[11]);
      $display("key[12] = 0x%016x", dut.keymem.key_mem[12]);
      $display("key[13] = 0x%016x", dut.keymem.key_mem[13]);
      $display("key[14] = 0x%016x", dut.keymem.key_mem[14]);
      $display("");
    end
  endtask // dump_keys


  //----------------------------------------------------------------
  // reset_dut()
  //
  // Toggle reset to put the DUT into a well known state.
  //----------------------------------------------------------------
  task reset_dut;
    begin
      $display("*** Toggle reset.");
      tb_reset_n = 0;
      #(2 * CLK_PERIOD);
      tb_reset_n = 1;
    end
  endtask // reset_dut


  //----------------------------------------------------------------
  // init_sim()
  //
  // Initialize all counters and testbed functionality as well
  // as setting the DUT inputs to defined values.
  //----------------------------------------------------------------
  task init_sim;
    begin
      cycle_ctr = 0;
      error_ctr = 0;
      tc_ctr    = 0;

      tb_clk     = 0;
      tb_reset_n = 1;
      tb_init    = 0;
      tb_next    = 0;
      tb_key     = {8{32'h00000000}};

      tb_block  = {4{32'h00000000}};
    end
  endtask // init_sim


  //----------------------------------------------------------------
  // display_test_result()
  //
  // Display the accumulated test results.
  //----------------------------------------------------------------
  task display_test_result;
    begin
      if (error_ctr == 0)
        begin
          $display("*** All %02d test cases completed successfully", tc_ctr);
        end
      else
        begin
          $display("*** %02d tests completed - %02d test cases did not complete successfully.",
                   tc_ctr, error_ctr);
        end
    end
  endtask // display_test_result


  //----------------------------------------------------------------
  // wait_ready()
  //
  // Wait for the ready flag in the dut to be set.
  //
  // Note: It is the callers responsibility to call the function
  // when the dut is actively processing and will in fact at some
  // point set the flag.
  //----------------------------------------------------------------
  task wait_ready;
    begin
      while (!tb_ready)
        begin
          #(CLK_PERIOD);
          if (DUMP_WAIT)
            begin
              dump_dut_state();
            end
        end
    end
  endtask // wait_ready


  //----------------------------------------------------------------
  // wait_valid()
  //
  // Wait for the result_valid flag in the dut to be set.
  //
  // Note: It is the callers responsibility to call the function
  // when the dut is actively processing a block and will in fact
  // at some point set the flag.
  //----------------------------------------------------------------
  task wait_valid;
    begin
      while (!tb_result_valid)
        begin
          #(CLK_PERIOD);
        end
    end
  endtask // wait_valid


  //----------------------------------------------------------------
  // cbc_mode_single_block_test()
  //
  // Perform ECB mode encryption or decryption single block test.
  //----------------------------------------------------------------
  task cbc_mode_single_block_test(input [7 : 0]   tc_number,
                                  input [255 : 0] key,
                                  input [127 : 0] iv,
                                  input [127 : 0] block,
                                  input [127 : 0] expected);
   begin
     $display("*** TC %0d ECB mode test started.", tc_number);
     tc_ctr = tc_ctr + 1;

     // Init the cipher with the given key and length.
     tb_key  = key;
     tb_iv   = iv;
     tb_init = 1;
     #(2 * CLK_PERIOD);
     tb_init = 0;
     wait_ready();

     $display("Key expansion done");
     $display("");

     dump_keys();


     // Perform encipher och decipher operation on the block.
     tb_block = block;
     tb_next = 1;
     #(2 * CLK_PERIOD);
     tb_next = 0;
     wait_ready();

     if (tb_result == expected)
       begin
         $display("*** TC %0d successful.", tc_number);
         $display("");
       end
     else
       begin
         $display("*** ERROR: TC %0d NOT successful.", tc_number);
         $display("Expected: 0x%032x", expected);
         $display("Got:      0x%032x", tb_result);
         $display("");

         error_ctr = error_ctr + 1;
       end
   end
  endtask // cbc_mode_single_block_test


  //----------------------------------------------------------------
  // aes_256_cbc_test
  // The main test functionality.
  // Test vectors copied from the follwing NIST documents.
  //
  // NIST SP 800-38A:
  // http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
  //
  // NIST FIPS-197, Appendix C:
  // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
  //
  // Test cases taken from NIST SP 800-38A:
  // http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
  //----------------------------------------------------------------
  initial
    begin : aes_256_cbc_test
      reg [255 : 0] aes256_key1;
      reg [255 : 0] aes256_key2;
      reg [255 : 0] aes256_key3;
      reg [255 : 0] aes256_key4;

      reg [127 : 0] ciphertext0;
      reg [127 : 0] ciphertext1;
      reg [127 : 0] ciphertext2;
      reg [127 : 0] ciphertext3;

      reg [127 : 0] cbc_256_dec_expected0;
      reg [127 : 0] cbc_256_dec_expected1;
      reg [127 : 0] cbc_256_dec_expected2;
      reg [127 : 0] cbc_256_dec_expected3;

      aes256_key0 = 256'hf884449e1c3c65afa80ce7c8a76ac565dd106c2d037371d08b91bf8978b1c296;
      aes256_key1 = 256'h8ab67eb42341c42c936ebc2f53f5fbeda5bff4f383f39cce27d0d00733fcb0cb;
      aes256_key2 = 256'hd14d179a1c6bb7118a1fe5932d1c2a49e018c50076d793c4c86ece98721fe978;
      aes256_key3 = 256'h9328e385b65d1866c65a5ba8677ab37e7e44ced5e0fd0bce37fa1b34d92a4c04;


      aes256_iv0 = 128'h43ac36b33d79a74e77e29f3a384d6a19;
      aes256_iv1 = 128'h492de5ecf8e692aa984face502c5bd3d;
      aes256_iv2 = 128'h55f761483ec4c9f094b6485104827501;
      aes256_iv3 = 128'h46fcec5ba9097361c508cebdc7231f1f;

      ciphertext0 = 128'h3fa4153ca0f82e4c07ae8b9f1b4d67fa;
      ciphertext1 = 128'h40d196401c77f54af23ec4619cd8b05b;
      ciphertext2 = 128'hac7f8ab6f2b61992b5c24fbdd3b9f189
      ciphertext3 = 128'h84f592f1df26c1414a79091b14682a60;

      cbc_256_dec_expected0 = 128'hcc24b927952881bc01a96ecd422bccf1;
      cbc_256_dec_expected1 = 128'ha1fcf33103baae6882047d6b5bacc62d;
      cbc_256_dec_expected2 = 128'h3cca05764c5ead5a8934b98385b8ee41;
      cbc_256_dec_expected3 = 128'h56442395860ea145791e0670ad3b9b91;


      $display("   -= Testbench for aes core started =-");
      $display("     ================================");
      $display("");

      init_sim();
      dump_dut_state();
      reset_dut();
      dump_dut_state();

      $display("");
      $display("CBC 256 bit key tests");
      $display("---------------------");

      cbc_mode_single_block_test(8'h1, aes256_key0, aes256_iv0, ciphertext0, ecb_256_enc_expected0);

      cbc_mode_single_block_test(8'h2, aes256_key1, aes256_iv1, ciphertext1, ecb_256_enc_expected1);

      cbc_mode_single_block_test(8'h3, aes256_key2, aes256_iv2, ciphertext2, ecb_256_enc_expected2);

      cbc_mode_single_block_test(8'h4, aes256_key3, aes256_iv3, ciphertext3, ecb_256_enc_expected3);

      display_test_result();
      $display("");
      $display("*** AES core simulation done. ***");
      $finish;
    end // aes_256_cbc_test
endmodule // tb_aes_256_cbc

//======================================================================
// EOF tb_aes_256_cbc.v
//======================================================================
