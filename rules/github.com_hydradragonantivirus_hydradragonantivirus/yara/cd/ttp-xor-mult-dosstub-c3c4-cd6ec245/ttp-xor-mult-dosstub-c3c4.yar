rule TTP_XOR_MULT_DOSStub_c3c4 {
  strings:
    $key_c3c4 = { 97 ac [2] e3 b4 [2] a4 b6 [2] e3 a7 [2] ad ab [2] a1 a1 [2] b6 aa [2] ad e4 [2] 90 }

  condition:
    any of them
}