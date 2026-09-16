rule TTP_XOR_MULT_DOSStub_307f {
  strings:
    $key_307f = { 64 17 [2] 10 0f [2] 57 0d [2] 10 1c [2] 5e 10 [2] 52 1a [2] 45 11 [2] 5e 5f [2] 63 }

  condition:
    any of them
}