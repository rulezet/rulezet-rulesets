rule TTP_XOR_MULT_DOSStub_b250 {
  strings:
    $key_b250 = { e6 38 [2] 92 20 [2] d5 22 [2] 92 33 [2] dc 3f [2] d0 35 [2] c7 3e [2] dc 70 [2] e1 }

  condition:
    any of them
}