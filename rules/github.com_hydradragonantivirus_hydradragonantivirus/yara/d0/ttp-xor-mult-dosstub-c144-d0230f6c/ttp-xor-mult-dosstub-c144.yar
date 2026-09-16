rule TTP_XOR_MULT_DOSStub_c144 {
  strings:
    $key_c144 = { 95 2c [2] e1 34 [2] a6 36 [2] e1 27 [2] af 2b [2] a3 21 [2] b4 2a [2] af 64 [2] 92 }

  condition:
    any of them
}