rule TTP_XOR_MULT_DOSStub_c314 {
  strings:
    $key_c314 = { 97 7c [2] e3 64 [2] a4 66 [2] e3 77 [2] ad 7b [2] a1 71 [2] b6 7a [2] ad 34 [2] 90 }

  condition:
    any of them
}