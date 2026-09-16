rule TTP_XOR_MULT_DOSStub_20f9 {
  strings:
    $key_20f9 = { 74 91 [2] 00 89 [2] 47 8b [2] 00 9a [2] 4e 96 [2] 42 9c [2] 55 97 [2] 4e d9 [2] 73 }

  condition:
    any of them
}