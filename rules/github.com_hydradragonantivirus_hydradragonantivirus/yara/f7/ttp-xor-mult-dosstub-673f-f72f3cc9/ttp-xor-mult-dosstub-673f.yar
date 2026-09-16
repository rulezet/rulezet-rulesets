rule TTP_XOR_MULT_DOSStub_673f {
  strings:
    $key_673f = { 33 57 [2] 47 4f [2] 00 4d [2] 47 5c [2] 09 50 [2] 05 5a [2] 12 51 [2] 09 1f [2] 34 }

  condition:
    any of them
}