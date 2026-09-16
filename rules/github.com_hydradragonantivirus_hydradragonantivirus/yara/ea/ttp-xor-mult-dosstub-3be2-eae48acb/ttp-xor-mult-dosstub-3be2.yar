rule TTP_XOR_MULT_DOSStub_3be2 {
  strings:
    $key_3be2 = { 6f 8a [2] 1b 92 [2] 5c 90 [2] 1b 81 [2] 55 8d [2] 59 87 [2] 4e 8c [2] 55 c2 [2] 68 }

  condition:
    any of them
}