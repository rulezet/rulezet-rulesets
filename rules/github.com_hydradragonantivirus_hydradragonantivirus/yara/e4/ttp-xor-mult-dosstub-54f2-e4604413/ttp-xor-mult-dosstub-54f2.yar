rule TTP_XOR_MULT_DOSStub_54f2 {
  strings:
    $key_54f2 = { 00 9a [2] 74 82 [2] 33 80 [2] 74 91 [2] 3a 9d [2] 36 97 [2] 21 9c [2] 3a d2 [2] 07 }

  condition:
    any of them
}