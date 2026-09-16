rule TTP_XOR_MULT_DOSStub_c277 {
  strings:
    $key_c277 = { 96 1f [2] e2 07 [2] a5 05 [2] e2 14 [2] ac 18 [2] a0 12 [2] b7 19 [2] ac 57 [2] 91 }

  condition:
    any of them
}