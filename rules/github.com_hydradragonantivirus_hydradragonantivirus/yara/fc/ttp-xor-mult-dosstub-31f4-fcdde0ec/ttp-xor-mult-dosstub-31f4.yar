rule TTP_XOR_MULT_DOSStub_31f4 {
  strings:
    $key_31f4 = { 65 9c [2] 11 84 [2] 56 86 [2] 11 97 [2] 5f 9b [2] 53 91 [2] 44 9a [2] 5f d4 [2] 62 }

  condition:
    any of them
}