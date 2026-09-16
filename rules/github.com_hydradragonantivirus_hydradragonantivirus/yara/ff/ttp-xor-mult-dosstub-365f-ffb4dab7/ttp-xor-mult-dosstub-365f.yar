rule TTP_XOR_MULT_DOSStub_365f {
  strings:
    $key_365f = { 62 37 [2] 16 2f [2] 51 2d [2] 16 3c [2] 58 30 [2] 54 3a [2] 43 31 [2] 58 7f [2] 65 }

  condition:
    any of them
}