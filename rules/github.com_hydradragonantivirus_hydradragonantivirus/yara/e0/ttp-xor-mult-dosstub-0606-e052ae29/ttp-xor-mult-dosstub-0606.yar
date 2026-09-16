rule TTP_XOR_MULT_DOSStub_0606 {
  strings:
    $key_0606 = { 52 6e [2] 26 76 [2] 61 74 [2] 26 65 [2] 68 69 [2] 64 63 [2] 73 68 [2] 68 26 [2] 55 }

  condition:
    any of them
}