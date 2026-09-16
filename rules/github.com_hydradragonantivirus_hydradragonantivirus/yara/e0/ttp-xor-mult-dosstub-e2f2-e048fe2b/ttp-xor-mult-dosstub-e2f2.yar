rule TTP_XOR_MULT_DOSStub_e2f2 {
  strings:
    $key_e2f2 = { b6 9a [2] c2 82 [2] 85 80 [2] c2 91 [2] 8c 9d [2] 80 97 [2] 97 9c [2] 8c d2 [2] b1 }

  condition:
    any of them
}