rule TTP_XOR_MULT_DOSStub_0100 {
  strings:
    $key_0100 = { 55 68 [2] 21 70 [2] 66 72 [2] 21 63 [2] 6f 6f [2] 63 65 [2] 74 6e [2] 6f 20 [2] 52 }

  condition:
    any of them
}