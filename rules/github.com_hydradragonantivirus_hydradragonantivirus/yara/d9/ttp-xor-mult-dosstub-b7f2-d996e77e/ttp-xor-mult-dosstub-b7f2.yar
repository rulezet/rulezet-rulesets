rule TTP_XOR_MULT_DOSStub_b7f2 {
  strings:
    $key_b7f2 = { e3 9a [2] 97 82 [2] d0 80 [2] 97 91 [2] d9 9d [2] d5 97 [2] c2 9c [2] d9 d2 [2] e4 }

  condition:
    any of them
}