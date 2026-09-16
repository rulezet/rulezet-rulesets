rule TTP_XOR_MULT_DOSStub_b775 {
  strings:
    $key_b775 = { e3 1d [2] 97 05 [2] d0 07 [2] 97 16 [2] d9 1a [2] d5 10 [2] c2 1b [2] d9 55 [2] e4 }

  condition:
    any of them
}