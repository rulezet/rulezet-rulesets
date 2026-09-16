rule TTP_XOR_MULT_DOSStub_306f {
  strings:
    $key_306f = { 64 07 [2] 10 1f [2] 57 1d [2] 10 0c [2] 5e 00 [2] 52 0a [2] 45 01 [2] 5e 4f [2] 63 }

  condition:
    any of them
}