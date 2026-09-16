rule TTP_XOR_MULT_DOSStub_7c3f {
  strings:
    $key_7c3f = { 28 57 [2] 5c 4f [2] 1b 4d [2] 5c 5c [2] 12 50 [2] 1e 5a [2] 09 51 [2] 12 1f [2] 2f }

  condition:
    any of them
}