rule TTP_XOR_MULT_DOSStub_0ff9 {
  strings:
    $key_0ff9 = { 5b 91 [2] 2f 89 [2] 68 8b [2] 2f 9a [2] 61 96 [2] 6d 9c [2] 7a 97 [2] 61 d9 [2] 5c }

  condition:
    any of them
}