rule TTP_XOR_MULT_DOSStub_b329 {
  strings:
    $key_b329 = { e7 41 [2] 93 59 [2] d4 5b [2] 93 4a [2] dd 46 [2] d1 4c [2] c6 47 [2] dd 09 [2] e0 }

  condition:
    any of them
}