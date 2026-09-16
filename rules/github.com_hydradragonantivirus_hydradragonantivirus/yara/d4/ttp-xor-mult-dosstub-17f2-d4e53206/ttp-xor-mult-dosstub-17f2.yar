rule TTP_XOR_MULT_DOSStub_17f2 {
  strings:
    $key_17f2 = { 43 9a [2] 37 82 [2] 70 80 [2] 37 91 [2] 79 9d [2] 75 97 [2] 62 9c [2] 79 d2 [2] 44 }

  condition:
    any of them
}