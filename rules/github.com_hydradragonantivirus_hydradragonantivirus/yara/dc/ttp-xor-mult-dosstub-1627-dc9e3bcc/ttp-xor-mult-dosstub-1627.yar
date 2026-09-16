rule TTP_XOR_MULT_DOSStub_1627 {
  strings:
    $key_1627 = { 42 4f [2] 36 57 [2] 71 55 [2] 36 44 [2] 78 48 [2] 74 42 [2] 63 49 [2] 78 07 [2] 45 }

  condition:
    any of them
}