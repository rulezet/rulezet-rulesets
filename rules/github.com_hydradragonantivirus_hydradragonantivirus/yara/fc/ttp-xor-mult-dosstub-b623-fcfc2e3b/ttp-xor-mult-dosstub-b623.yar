rule TTP_XOR_MULT_DOSStub_b623 {
  strings:
    $key_b623 = { e2 4b [2] 96 53 [2] d1 51 [2] 96 40 [2] d8 4c [2] d4 46 [2] c3 4d [2] d8 03 [2] e5 }

  condition:
    any of them
}