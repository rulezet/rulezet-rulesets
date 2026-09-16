rule TTP_XOR_MULT_DOSStub_cc16 {
  strings:
    $key_cc16 = { 98 7e [2] ec 66 [2] ab 64 [2] ec 75 [2] a2 79 [2] ae 73 [2] b9 78 [2] a2 36 [2] 9f }

  condition:
    any of them
}