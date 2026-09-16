rule TTP_XOR_MULT_DOSStub_3be4 {
  strings:
    $key_3be4 = { 6f 8c [2] 1b 94 [2] 5c 96 [2] 1b 87 [2] 55 8b [2] 59 81 [2] 4e 8a [2] 55 c4 [2] 68 }

  condition:
    any of them
}