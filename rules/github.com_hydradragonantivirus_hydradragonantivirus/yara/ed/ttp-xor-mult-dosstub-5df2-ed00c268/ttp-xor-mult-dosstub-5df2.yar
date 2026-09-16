rule TTP_XOR_MULT_DOSStub_5df2 {
  strings:
    $key_5df2 = { 09 9a [2] 7d 82 [2] 3a 80 [2] 7d 91 [2] 33 9d [2] 3f 97 [2] 28 9c [2] 33 d2 [2] 0e }

  condition:
    any of them
}