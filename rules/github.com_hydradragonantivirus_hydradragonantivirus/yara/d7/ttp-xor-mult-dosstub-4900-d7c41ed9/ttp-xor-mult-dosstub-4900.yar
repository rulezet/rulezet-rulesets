rule TTP_XOR_MULT_DOSStub_4900 {
  strings:
    $key_4900 = { 1d 68 [2] 69 70 [2] 2e 72 [2] 69 63 [2] 27 6f [2] 2b 65 [2] 3c 6e [2] 27 20 [2] 1a }

  condition:
    any of them
}