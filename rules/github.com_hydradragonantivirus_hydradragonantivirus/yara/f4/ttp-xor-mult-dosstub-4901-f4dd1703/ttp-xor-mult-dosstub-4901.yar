rule TTP_XOR_MULT_DOSStub_4901 {
  strings:
    $key_4901 = { 1d 69 [2] 69 71 [2] 2e 73 [2] 69 62 [2] 27 6e [2] 2b 64 [2] 3c 6f [2] 27 21 [2] 1a }

  condition:
    any of them
}