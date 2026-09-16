rule TTP_XOR_MULT_DOSStub_c386 {
  strings:
    $key_c386 = { 97 ee [2] e3 f6 [2] a4 f4 [2] e3 e5 [2] ad e9 [2] a1 e3 [2] b6 e8 [2] ad a6 [2] 90 }

  condition:
    any of them
}