rule TTP_XOR_MULT_DOSStub_3502 {
  strings:
    $key_3502 = { 61 6a [2] 15 72 [2] 52 70 [2] 15 61 [2] 5b 6d [2] 57 67 [2] 40 6c [2] 5b 22 [2] 66 }

  condition:
    any of them
}