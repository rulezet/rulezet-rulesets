rule TTP_XOR_MULT_DOSStub_4af2 {
  strings:
    $key_4af2 = { 1e 9a [2] 6a 82 [2] 2d 80 [2] 6a 91 [2] 24 9d [2] 28 97 [2] 3f 9c [2] 24 d2 [2] 19 }

  condition:
    any of them
}