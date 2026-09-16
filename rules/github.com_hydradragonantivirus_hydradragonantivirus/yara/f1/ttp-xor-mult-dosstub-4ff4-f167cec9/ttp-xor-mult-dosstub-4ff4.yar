rule TTP_XOR_MULT_DOSStub_4ff4 {
  strings:
    $key_4ff4 = { 1b 9c [2] 6f 84 [2] 28 86 [2] 6f 97 [2] 21 9b [2] 2d 91 [2] 3a 9a [2] 21 d4 [2] 1c }

  condition:
    any of them
}