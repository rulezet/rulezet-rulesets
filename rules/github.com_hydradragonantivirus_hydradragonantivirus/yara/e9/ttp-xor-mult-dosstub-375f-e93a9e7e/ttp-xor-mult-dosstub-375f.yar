rule TTP_XOR_MULT_DOSStub_375f {
  strings:
    $key_375f = { 63 37 [2] 17 2f [2] 50 2d [2] 17 3c [2] 59 30 [2] 55 3a [2] 42 31 [2] 59 7f [2] 64 }

  condition:
    any of them
}