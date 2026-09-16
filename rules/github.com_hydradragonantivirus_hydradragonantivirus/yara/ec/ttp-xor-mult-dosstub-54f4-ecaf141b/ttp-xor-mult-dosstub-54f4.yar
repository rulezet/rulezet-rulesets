rule TTP_XOR_MULT_DOSStub_54f4 {
  strings:
    $key_54f4 = { 00 9c [2] 74 84 [2] 33 86 [2] 74 97 [2] 3a 9b [2] 36 91 [2] 21 9a [2] 3a d4 [2] 07 }

  condition:
    any of them
}