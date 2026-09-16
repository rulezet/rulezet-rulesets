rule TTP_XOR_MULT_DOSStub_103f {
  strings:
    $key_103f = { 44 57 [2] 30 4f [2] 77 4d [2] 30 5c [2] 7e 50 [2] 72 5a [2] 65 51 [2] 7e 1f [2] 43 }

  condition:
    any of them
}