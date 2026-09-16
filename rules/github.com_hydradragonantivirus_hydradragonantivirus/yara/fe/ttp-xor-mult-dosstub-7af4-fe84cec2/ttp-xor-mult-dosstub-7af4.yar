rule TTP_XOR_MULT_DOSStub_7af4 {
  strings:
    $key_7af4 = { 2e 9c [2] 5a 84 [2] 1d 86 [2] 5a 97 [2] 14 9b [2] 18 91 [2] 0f 9a [2] 14 d4 [2] 29 }

  condition:
    any of them
}