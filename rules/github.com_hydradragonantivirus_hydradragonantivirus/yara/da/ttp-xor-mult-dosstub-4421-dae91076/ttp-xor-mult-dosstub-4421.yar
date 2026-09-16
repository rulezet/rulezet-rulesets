rule TTP_XOR_MULT_DOSStub_4421 {
  strings:
    $key_4421 = { 10 49 [2] 64 51 [2] 23 53 [2] 64 42 [2] 2a 4e [2] 26 44 [2] 31 4f [2] 2a 01 [2] 17 }

  condition:
    any of them
}