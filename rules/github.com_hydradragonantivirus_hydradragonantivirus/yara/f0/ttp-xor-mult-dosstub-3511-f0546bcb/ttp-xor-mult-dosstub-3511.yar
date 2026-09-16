rule TTP_XOR_MULT_DOSStub_3511 {
  strings:
    $key_3511 = { 61 79 [2] 15 61 [2] 52 63 [2] 15 72 [2] 5b 7e [2] 57 74 [2] 40 7f [2] 5b 31 [2] 66 }

  condition:
    any of them
}