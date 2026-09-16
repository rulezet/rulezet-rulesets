rule TTP_XOR_MULT_DOSStub_72f9 {
  strings:
    $key_72f9 = { 26 91 [2] 52 89 [2] 15 8b [2] 52 9a [2] 1c 96 [2] 10 9c [2] 07 97 [2] 1c d9 [2] 21 }

  condition:
    any of them
}