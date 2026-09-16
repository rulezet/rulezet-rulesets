rule TTP_XOR_MULT_DOSStub_c377 {
  strings:
    $key_c377 = { 97 1f [2] e3 07 [2] a4 05 [2] e3 14 [2] ad 18 [2] a1 12 [2] b6 19 [2] ad 57 [2] 90 }

  condition:
    any of them
}