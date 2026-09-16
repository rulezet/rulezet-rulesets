rule TTP_XOR_MULT_DOSStub_490f {
  strings:
    $key_490f = { 1d 67 [2] 69 7f [2] 2e 7d [2] 69 6c [2] 27 60 [2] 2b 6a [2] 3c 61 [2] 27 2f [2] 1a }

  condition:
    any of them
}