rule TTP_XOR_MULT_DOSStub_7c0f {
  strings:
    $key_7c0f = { 28 67 [2] 5c 7f [2] 1b 7d [2] 5c 6c [2] 12 60 [2] 1e 6a [2] 09 61 [2] 12 2f [2] 2f }

  condition:
    any of them
}