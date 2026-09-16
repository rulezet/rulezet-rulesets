rule TTP_XOR_MULT_DOSStub_2111 {
  strings:
    $key_2111 = { 75 79 [2] 01 61 [2] 46 63 [2] 01 72 [2] 4f 7e [2] 43 74 [2] 54 7f [2] 4f 31 [2] 72 }

  condition:
    any of them
}