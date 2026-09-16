rule TTP_XOR_MULT_DOSStub_4ff9 {
  strings:
    $key_4ff9 = { 1b 91 [2] 6f 89 [2] 28 8b [2] 6f 9a [2] 21 96 [2] 2d 9c [2] 3a 97 [2] 21 d9 [2] 1c }

  condition:
    any of them
}