rule TTP_XOR_MULT_DOSStub_c389 {
  strings:
    $key_c389 = { 97 e1 [2] e3 f9 [2] a4 fb [2] e3 ea [2] ad e6 [2] a1 ec [2] b6 e7 [2] ad a9 [2] 90 }

  condition:
    any of them
}