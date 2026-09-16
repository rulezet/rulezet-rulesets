rule TTP_XOR_MULT_DOSStub_c3c7 {
  strings:
    $key_c3c7 = { 97 af [2] e3 b7 [2] a4 b5 [2] e3 a4 [2] ad a8 [2] a1 a2 [2] b6 a9 [2] ad e7 [2] 90 }

  condition:
    any of them
}