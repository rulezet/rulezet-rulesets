rule TTP_XOR_MULT_DOSStub_3c26 {
  strings:
    $key_3c26 = { 68 4e [2] 1c 56 [2] 5b 54 [2] 1c 45 [2] 52 49 [2] 5e 43 [2] 49 48 [2] 52 06 [2] 6f }

  condition:
    any of them
}