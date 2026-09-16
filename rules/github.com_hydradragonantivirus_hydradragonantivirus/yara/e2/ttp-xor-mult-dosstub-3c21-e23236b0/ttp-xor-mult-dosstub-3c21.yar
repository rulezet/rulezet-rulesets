rule TTP_XOR_MULT_DOSStub_3c21 {
  strings:
    $key_3c21 = { 68 49 [2] 1c 51 [2] 5b 53 [2] 1c 42 [2] 52 4e [2] 5e 44 [2] 49 4f [2] 52 01 [2] 6f }

  condition:
    any of them
}