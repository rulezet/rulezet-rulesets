rule TTP_XOR_MULT_DOSStub_c163 {
  strings:
    $key_c163 = { 95 0b [2] e1 13 [2] a6 11 [2] e1 00 [2] af 0c [2] a3 06 [2] b4 0d [2] af 43 [2] 92 }

  condition:
    any of them
}