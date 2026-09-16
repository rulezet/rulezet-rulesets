rule TTP_XOR_MULT_DOSStub_3101 {
  strings:
    $key_3101 = { 65 69 [2] 11 71 [2] 56 73 [2] 11 62 [2] 5f 6e [2] 53 64 [2] 44 6f [2] 5f 21 [2] 62 }

  condition:
    any of them
}