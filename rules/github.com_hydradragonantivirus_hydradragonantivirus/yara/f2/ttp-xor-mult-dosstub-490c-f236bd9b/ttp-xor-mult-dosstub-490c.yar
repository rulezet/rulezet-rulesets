rule TTP_XOR_MULT_DOSStub_490c {
  strings:
    $key_490c = { 1d 64 [2] 69 7c [2] 2e 7e [2] 69 6f [2] 27 63 [2] 2b 69 [2] 3c 62 [2] 27 2c [2] 1a }

  condition:
    any of them
}