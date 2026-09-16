rule TTP_XOR_MULT_DOSStub_cc06 {
  strings:
    $key_cc06 = { 98 6e [2] ec 76 [2] ab 74 [2] ec 65 [2] a2 69 [2] ae 63 [2] b9 68 [2] a2 26 [2] 9f }

  condition:
    any of them
}