rule TTP_XOR_MULT_DOSStub_b216 {
  strings:
    $key_b216 = { e6 7e [2] 92 66 [2] d5 64 [2] 92 75 [2] dc 79 [2] d0 73 [2] c7 78 [2] dc 36 [2] e1 }

  condition:
    any of them
}