rule TTP_XOR_MULT_DOSStub_b271 {
  strings:
    $key_b271 = { e6 19 [2] 92 01 [2] d5 03 [2] 92 12 [2] dc 1e [2] d0 14 [2] c7 1f [2] dc 51 [2] e1 }

  condition:
    any of them
}