rule TTP_XOR_MULT_DOSStub_6ff9 {
  strings:
    $key_6ff9 = { 3b 91 [2] 4f 89 [2] 08 8b [2] 4f 9a [2] 01 96 [2] 0d 9c [2] 1a 97 [2] 01 d9 [2] 3c }

  condition:
    any of them
}