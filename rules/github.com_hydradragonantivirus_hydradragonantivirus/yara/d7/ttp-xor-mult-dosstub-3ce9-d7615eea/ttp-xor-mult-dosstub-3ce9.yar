rule TTP_XOR_MULT_DOSStub_3ce9 {
  strings:
    $key_3ce9 = { 68 81 [2] 1c 99 [2] 5b 9b [2] 1c 8a [2] 52 86 [2] 5e 8c [2] 49 87 [2] 52 c9 [2] 6f }

  condition:
    any of them
}