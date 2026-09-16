rule TTP_XOR_MULT_DOSStub_b653 {
  strings:
    $key_b653 = { e2 3b [2] 96 23 [2] d1 21 [2] 96 30 [2] d8 3c [2] d4 36 [2] c3 3d [2] d8 73 [2] e5 }

  condition:
    any of them
}