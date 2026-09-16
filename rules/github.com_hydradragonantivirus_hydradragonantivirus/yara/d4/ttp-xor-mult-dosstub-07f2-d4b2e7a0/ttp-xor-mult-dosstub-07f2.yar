rule TTP_XOR_MULT_DOSStub_07f2 {
  strings:
    $key_07f2 = { 53 9a [2] 27 82 [2] 60 80 [2] 27 91 [2] 69 9d [2] 65 97 [2] 72 9c [2] 69 d2 [2] 54 }

  condition:
    any of them
}