rule TTP_XOR_MULT_DOSStub_497f {
  strings:
    $key_497f = { 1d 17 [2] 69 0f [2] 2e 0d [2] 69 1c [2] 27 10 [2] 2b 1a [2] 3c 11 [2] 27 5f [2] 1a }

  condition:
    any of them
}