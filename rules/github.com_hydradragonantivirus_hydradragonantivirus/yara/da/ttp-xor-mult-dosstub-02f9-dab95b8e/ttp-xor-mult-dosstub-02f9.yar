rule TTP_XOR_MULT_DOSStub_02f9 {
  strings:
    $key_02f9 = { 56 91 [2] 22 89 [2] 65 8b [2] 22 9a [2] 6c 96 [2] 60 9c [2] 77 97 [2] 6c d9 [2] 51 }

  condition:
    any of them
}