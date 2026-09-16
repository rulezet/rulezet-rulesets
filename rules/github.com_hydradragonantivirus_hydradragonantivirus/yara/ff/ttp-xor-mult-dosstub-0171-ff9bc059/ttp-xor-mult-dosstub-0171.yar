rule TTP_XOR_MULT_DOSStub_0171 {
  strings:
    $key_0171 = { 55 19 [2] 21 01 [2] 66 03 [2] 21 12 [2] 6f 1e [2] 63 14 [2] 74 1f [2] 6f 51 [2] 52 }

  condition:
    any of them
}