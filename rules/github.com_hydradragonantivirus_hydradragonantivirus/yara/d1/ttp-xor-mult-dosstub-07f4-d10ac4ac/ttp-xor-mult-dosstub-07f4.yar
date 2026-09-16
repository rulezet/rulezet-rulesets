rule TTP_XOR_MULT_DOSStub_07f4 {
  strings:
    $key_07f4 = { 53 9c [2] 27 84 [2] 60 86 [2] 27 97 [2] 69 9b [2] 65 91 [2] 72 9a [2] 69 d4 [2] 54 }

  condition:
    any of them
}