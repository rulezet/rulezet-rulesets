rule TTP_XOR_MULT_DOSStub_b764 {
  strings:
    $key_b764 = { e3 0c [2] 97 14 [2] d0 16 [2] 97 07 [2] d9 0b [2] d5 01 [2] c2 0a [2] d9 44 [2] e4 }

  condition:
    any of them
}