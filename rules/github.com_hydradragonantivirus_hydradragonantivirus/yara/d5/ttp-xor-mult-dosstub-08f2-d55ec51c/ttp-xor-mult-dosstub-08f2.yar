rule TTP_XOR_MULT_DOSStub_08f2 {
  strings:
    $key_08f2 = { 5c 9a [2] 28 82 [2] 6f 80 [2] 28 91 [2] 66 9d [2] 6a 97 [2] 7d 9c [2] 66 d2 [2] 5b }

  condition:
    any of them
}