rule TTP_XOR_MULT_DOSStub_e5f2 {
  strings:
    $key_e5f2 = { b1 9a [2] c5 82 [2] 82 80 [2] c5 91 [2] 8b 9d [2] 87 97 [2] 90 9c [2] 8b d2 [2] b6 }

  condition:
    any of them
}