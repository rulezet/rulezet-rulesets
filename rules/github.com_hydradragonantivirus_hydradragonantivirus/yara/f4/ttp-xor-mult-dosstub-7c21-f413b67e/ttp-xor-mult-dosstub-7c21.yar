rule TTP_XOR_MULT_DOSStub_7c21 {
  strings:
    $key_7c21 = { 28 49 [2] 5c 51 [2] 1b 53 [2] 5c 42 [2] 12 4e [2] 1e 44 [2] 09 4f [2] 12 01 [2] 2f }

  condition:
    any of them
}