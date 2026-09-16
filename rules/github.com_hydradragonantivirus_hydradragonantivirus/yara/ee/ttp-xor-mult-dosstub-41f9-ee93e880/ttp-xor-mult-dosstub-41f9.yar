rule TTP_XOR_MULT_DOSStub_41f9 {
  strings:
    $key_41f9 = { 15 91 [2] 61 89 [2] 26 8b [2] 61 9a [2] 2f 96 [2] 23 9c [2] 34 97 [2] 2f d9 [2] 12 }

  condition:
    any of them
}