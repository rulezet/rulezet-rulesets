rule TTP_XOR_MULT_DOSStub_0650 {
  strings:
    $key_0650 = { 52 38 [2] 26 20 [2] 61 22 [2] 26 33 [2] 68 3f [2] 64 35 [2] 73 3e [2] 68 70 [2] 55 }

  condition:
    any of them
}