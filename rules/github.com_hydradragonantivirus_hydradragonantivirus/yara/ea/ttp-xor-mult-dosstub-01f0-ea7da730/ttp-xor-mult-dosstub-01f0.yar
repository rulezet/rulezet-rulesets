rule TTP_XOR_MULT_DOSStub_01f0 {
  strings:
    $key_01f0 = { 55 98 [2] 21 80 [2] 66 82 [2] 21 93 [2] 6f 9f [2] 63 95 [2] 74 9e [2] 6f d0 [2] 52 }

  condition:
    any of them
}