rule TTP_XOR_MULT_DOSStub_cc43 {
  strings:
    $key_cc43 = { 98 2b [2] ec 33 [2] ab 31 [2] ec 20 [2] a2 2c [2] ae 26 [2] b9 2d [2] a2 63 [2] 9f }

  condition:
    any of them
}