rule TTP_XOR_MULT_DOSStub_183f {
  strings:
    $key_183f = { 4c 57 [2] 38 4f [2] 7f 4d [2] 38 5c [2] 76 50 [2] 7a 5a [2] 6d 51 [2] 76 1f [2] 4b }

  condition:
    any of them
}