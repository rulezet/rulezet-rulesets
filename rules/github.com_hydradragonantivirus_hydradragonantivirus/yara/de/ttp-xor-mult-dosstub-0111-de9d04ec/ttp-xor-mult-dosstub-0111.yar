rule TTP_XOR_MULT_DOSStub_0111 {
  strings:
    $key_0111 = { 55 79 [2] 21 61 [2] 66 63 [2] 21 72 [2] 6f 7e [2] 63 74 [2] 74 7f [2] 6f 31 [2] 52 }

  condition:
    any of them
}