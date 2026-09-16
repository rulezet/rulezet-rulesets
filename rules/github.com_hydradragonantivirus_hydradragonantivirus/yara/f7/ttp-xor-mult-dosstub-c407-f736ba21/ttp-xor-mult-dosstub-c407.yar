rule TTP_XOR_MULT_DOSStub_c407 {
  strings:
    $key_c407 = { 90 6f [2] e4 77 [2] a3 75 [2] e4 64 [2] aa 68 [2] a6 62 [2] b1 69 [2] aa 27 [2] 97 }

  condition:
    any of them
}