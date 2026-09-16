rule TTP_XOR_MULT_DOSStub_490a {
  strings:
    $key_490a = { 1d 62 [2] 69 7a [2] 2e 78 [2] 69 69 [2] 27 65 [2] 2b 6f [2] 3c 64 [2] 27 2a [2] 1a }

  condition:
    any of them
}