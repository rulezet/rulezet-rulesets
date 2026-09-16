rule TTP_XOR_MULT_DOSStub_b766 {
  strings:
    $key_b766 = { e3 0e [2] 97 16 [2] d0 14 [2] 97 05 [2] d9 09 [2] d5 03 [2] c2 08 [2] d9 46 [2] e4 }

  condition:
    any of them
}