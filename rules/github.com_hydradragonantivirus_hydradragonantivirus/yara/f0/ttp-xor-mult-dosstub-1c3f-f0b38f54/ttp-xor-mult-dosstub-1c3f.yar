rule TTP_XOR_MULT_DOSStub_1c3f {
  strings:
    $key_1c3f = { 48 57 [2] 3c 4f [2] 7b 4d [2] 3c 5c [2] 72 50 [2] 7e 5a [2] 69 51 [2] 72 1f [2] 4f }

  condition:
    any of them
}