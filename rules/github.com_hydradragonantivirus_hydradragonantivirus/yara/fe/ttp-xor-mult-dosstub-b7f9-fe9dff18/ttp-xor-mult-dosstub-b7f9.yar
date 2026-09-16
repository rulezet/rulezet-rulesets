rule TTP_XOR_MULT_DOSStub_b7f9 {
  strings:
    $key_b7f9 = { e3 91 [2] 97 89 [2] d0 8b [2] 97 9a [2] d9 96 [2] d5 9c [2] c2 97 [2] d9 d9 [2] e4 }

  condition:
    any of them
}