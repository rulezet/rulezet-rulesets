rule TTP_XOR_MULT_DOSStub_e6f2 {
  strings:
    $key_e6f2 = { b2 9a [2] c6 82 [2] 81 80 [2] c6 91 [2] 88 9d [2] 84 97 [2] 93 9c [2] 88 d2 [2] b5 }

  condition:
    any of them
}