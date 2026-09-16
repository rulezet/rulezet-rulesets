rule TTP_XOR_MULT_DOSStub_491f {
  strings:
    $key_491f = { 1d 77 [2] 69 6f [2] 2e 6d [2] 69 7c [2] 27 70 [2] 2b 7a [2] 3c 71 [2] 27 3f [2] 1a }

  condition:
    any of them
}