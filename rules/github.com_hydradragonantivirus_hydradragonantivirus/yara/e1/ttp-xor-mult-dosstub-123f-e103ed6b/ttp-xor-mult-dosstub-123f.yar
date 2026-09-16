rule TTP_XOR_MULT_DOSStub_123f {
  strings:
    $key_123f = { 46 57 [2] 32 4f [2] 75 4d [2] 32 5c [2] 7c 50 [2] 70 5a [2] 67 51 [2] 7c 1f [2] 41 }

  condition:
    any of them
}