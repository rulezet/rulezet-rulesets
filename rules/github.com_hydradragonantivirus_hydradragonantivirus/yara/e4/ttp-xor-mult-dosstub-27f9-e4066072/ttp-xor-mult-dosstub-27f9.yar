rule TTP_XOR_MULT_DOSStub_27f9 {
  strings:
    $key_27f9 = { 73 91 [2] 07 89 [2] 40 8b [2] 07 9a [2] 49 96 [2] 45 9c [2] 52 97 [2] 49 d9 [2] 74 }

  condition:
    any of them
}