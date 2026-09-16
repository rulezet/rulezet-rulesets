rule TTP_XOR_MULT_DOSStub_c307 {
  strings:
    $key_c307 = { 97 6f [2] e3 77 [2] a4 75 [2] e3 64 [2] ad 68 [2] a1 62 [2] b6 69 [2] ad 27 [2] 90 }

  condition:
    any of them
}