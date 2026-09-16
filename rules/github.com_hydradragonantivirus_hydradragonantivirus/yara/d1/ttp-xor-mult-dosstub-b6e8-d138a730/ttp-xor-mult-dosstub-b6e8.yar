rule TTP_XOR_MULT_DOSStub_b6e8 {
  strings:
    $key_b6e8 = { e2 80 [2] 96 98 [2] d1 9a [2] 96 8b [2] d8 87 [2] d4 8d [2] c3 86 [2] d8 c8 [2] e5 }

  condition:
    any of them
}