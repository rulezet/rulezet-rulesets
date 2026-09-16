rule TTP_XOR_MULT_DOSStub_f4e0 {
  strings:
    $key_f4e0 = { a0 88 [2] d4 90 [2] 93 92 [2] d4 83 [2] 9a 8f [2] 96 85 [2] 81 8e [2] 9a c0 [2] a7 }

  condition:
    any of them
}