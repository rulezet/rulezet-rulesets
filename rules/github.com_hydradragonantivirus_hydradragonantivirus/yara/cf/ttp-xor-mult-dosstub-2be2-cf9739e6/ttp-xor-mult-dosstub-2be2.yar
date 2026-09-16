rule TTP_XOR_MULT_DOSStub_2be2 {
  strings:
    $key_2be2 = { 7f 8a [2] 0b 92 [2] 4c 90 [2] 0b 81 [2] 45 8d [2] 49 87 [2] 5e 8c [2] 45 c2 [2] 78 }

  condition:
    any of them
}