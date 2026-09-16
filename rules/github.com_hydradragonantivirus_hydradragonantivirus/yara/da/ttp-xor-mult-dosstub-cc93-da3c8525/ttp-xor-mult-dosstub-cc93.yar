rule TTP_XOR_MULT_DOSStub_cc93 {
  strings:
    $key_cc93 = { 98 fb [2] ec e3 [2] ab e1 [2] ec f0 [2] a2 fc [2] ae f6 [2] b9 fd [2] a2 b3 [2] 9f }

  condition:
    any of them
}