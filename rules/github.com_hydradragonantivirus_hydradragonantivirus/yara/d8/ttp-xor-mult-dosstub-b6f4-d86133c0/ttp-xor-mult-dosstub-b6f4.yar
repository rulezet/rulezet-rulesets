rule TTP_XOR_MULT_DOSStub_b6f4 {
  strings:
    $key_b6f4 = { e2 9c [2] 96 84 [2] d1 86 [2] 96 97 [2] d8 9b [2] d4 91 [2] c3 9a [2] d8 d4 [2] e5 }

  condition:
    any of them
}