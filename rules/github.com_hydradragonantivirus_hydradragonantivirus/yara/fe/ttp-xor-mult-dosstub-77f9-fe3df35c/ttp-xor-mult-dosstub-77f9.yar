rule TTP_XOR_MULT_DOSStub_77f9 {
  strings:
    $key_77f9 = { 23 91 [2] 57 89 [2] 10 8b [2] 57 9a [2] 19 96 [2] 15 9c [2] 02 97 [2] 19 d9 [2] 24 }

  condition:
    any of them
}