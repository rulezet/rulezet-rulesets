rule TTP_XOR_MULT_DOSStub_c164 {
  strings:
    $key_c164 = { 95 0c [2] e1 14 [2] a6 16 [2] e1 07 [2] af 0b [2] a3 01 [2] b4 0a [2] af 44 [2] 92 }

  condition:
    any of them
}