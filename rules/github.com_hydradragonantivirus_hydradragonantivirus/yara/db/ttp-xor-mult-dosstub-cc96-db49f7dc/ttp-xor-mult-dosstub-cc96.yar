rule TTP_XOR_MULT_DOSStub_cc96 {
  strings:
    $key_cc96 = { 98 fe [2] ec e6 [2] ab e4 [2] ec f5 [2] a2 f9 [2] ae f3 [2] b9 f8 [2] a2 b6 [2] 9f }

  condition:
    any of them
}