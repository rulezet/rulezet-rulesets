rule TTP_XOR_MULT_DOSStub_4c26 {
  strings:
    $key_4c26 = { 18 4e [2] 6c 56 [2] 2b 54 [2] 6c 45 [2] 22 49 [2] 2e 43 [2] 39 48 [2] 22 06 [2] 1f }

  condition:
    any of them
}