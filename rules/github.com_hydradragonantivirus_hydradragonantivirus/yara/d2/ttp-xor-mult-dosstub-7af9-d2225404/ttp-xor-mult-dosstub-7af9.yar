rule TTP_XOR_MULT_DOSStub_7af9 {
  strings:
    $key_7af9 = { 2e 91 [2] 5a 89 [2] 1d 8b [2] 5a 9a [2] 14 96 [2] 18 9c [2] 0f 97 [2] 14 d9 [2] 29 }

  condition:
    any of them
}