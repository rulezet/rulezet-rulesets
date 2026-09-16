rule TTP_XOR_MULT_DOSStub_7c7f {
  strings:
    $key_7c7f = { 28 17 [2] 5c 0f [2] 1b 0d [2] 5c 1c [2] 12 10 [2] 1e 1a [2] 09 11 [2] 12 5f [2] 2f }

  condition:
    any of them
}