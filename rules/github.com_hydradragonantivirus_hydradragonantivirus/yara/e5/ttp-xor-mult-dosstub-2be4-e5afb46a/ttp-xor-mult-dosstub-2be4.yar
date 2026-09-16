rule TTP_XOR_MULT_DOSStub_2be4 {
  strings:
    $key_2be4 = { 7f 8c [2] 0b 94 [2] 4c 96 [2] 0b 87 [2] 45 8b [2] 49 81 [2] 5e 8a [2] 45 c4 [2] 78 }

  condition:
    any of them
}