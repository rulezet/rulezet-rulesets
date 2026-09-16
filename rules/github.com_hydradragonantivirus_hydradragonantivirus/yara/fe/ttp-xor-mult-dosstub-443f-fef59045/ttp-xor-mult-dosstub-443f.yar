rule TTP_XOR_MULT_DOSStub_443f {
  strings:
    $key_443f = { 10 57 [2] 64 4f [2] 23 4d [2] 64 5c [2] 2a 50 [2] 26 5a [2] 31 51 [2] 2a 1f [2] 17 }

  condition:
    any of them
}