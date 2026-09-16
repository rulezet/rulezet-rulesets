rule TTP_XOR_MULT_DOSStub_c174 {
  strings:
    $key_c174 = { 95 1c [2] e1 04 [2] a6 06 [2] e1 17 [2] af 1b [2] a3 11 [2] b4 1a [2] af 54 [2] 92 }

  condition:
    any of them
}