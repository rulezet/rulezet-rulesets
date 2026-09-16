rule TTP_XOR_MULT_DOSStub_e7f2 {
  strings:
    $key_e7f2 = { b3 9a [2] c7 82 [2] 80 80 [2] c7 91 [2] 89 9d [2] 85 97 [2] 92 9c [2] 89 d2 [2] b4 }

  condition:
    any of them
}