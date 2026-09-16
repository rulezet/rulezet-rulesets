rule TTP_XOR_MULT_DOSStub_2f54 {
  strings:
    $key_2f54 = { 7b 3c [2] 0f 24 [2] 48 26 [2] 0f 37 [2] 41 3b [2] 4d 31 [2] 5a 3a [2] 41 74 [2] 7c }

  condition:
    any of them
}