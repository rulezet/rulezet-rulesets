rule TTP_XOR_MULT_DOSStub_38f2 {
  strings:
    $key_38f2 = { 6c 9a [2] 18 82 [2] 5f 80 [2] 18 91 [2] 56 9d [2] 5a 97 [2] 4d 9c [2] 56 d2 [2] 6b }

  condition:
    any of them
}