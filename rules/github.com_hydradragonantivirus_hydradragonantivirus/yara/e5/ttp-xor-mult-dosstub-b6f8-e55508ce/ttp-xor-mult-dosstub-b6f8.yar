rule TTP_XOR_MULT_DOSStub_b6f8 {
  strings:
    $key_b6f8 = { e2 90 [2] 96 88 [2] d1 8a [2] 96 9b [2] d8 97 [2] d4 9d [2] c3 96 [2] d8 d8 [2] e5 }

  condition:
    any of them
}