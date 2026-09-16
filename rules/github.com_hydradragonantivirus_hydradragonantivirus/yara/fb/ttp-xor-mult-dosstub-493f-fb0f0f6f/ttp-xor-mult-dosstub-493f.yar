rule TTP_XOR_MULT_DOSStub_493f {
  strings:
    $key_493f = { 1d 57 [2] 69 4f [2] 2e 4d [2] 69 5c [2] 27 50 [2] 2b 5a [2] 3c 51 [2] 27 1f [2] 1a }

  condition:
    any of them
}