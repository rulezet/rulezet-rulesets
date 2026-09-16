rule TTP_XOR_MULT_DOSStub_b616 {
  strings:
    $key_b616 = { e2 7e [2] 96 66 [2] d1 64 [2] 96 75 [2] d8 79 [2] d4 73 [2] c3 78 [2] d8 36 [2] e5 }

  condition:
    any of them
}