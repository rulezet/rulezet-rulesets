rule TTP_XOR_MULT_DOSStub_3c31 {
  strings:
    $key_3c31 = { 68 59 [2] 1c 41 [2] 5b 43 [2] 1c 52 [2] 52 5e [2] 5e 54 [2] 49 5f [2] 52 11 [2] 6f }

  condition:
    any of them
}