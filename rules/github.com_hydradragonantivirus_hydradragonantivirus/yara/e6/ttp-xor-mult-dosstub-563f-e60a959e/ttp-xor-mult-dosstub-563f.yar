rule TTP_XOR_MULT_DOSStub_563f {
  strings:
    $key_563f = { 02 57 [2] 76 4f [2] 31 4d [2] 76 5c [2] 38 50 [2] 34 5a [2] 23 51 [2] 38 1f [2] 05 }

  condition:
    any of them
}