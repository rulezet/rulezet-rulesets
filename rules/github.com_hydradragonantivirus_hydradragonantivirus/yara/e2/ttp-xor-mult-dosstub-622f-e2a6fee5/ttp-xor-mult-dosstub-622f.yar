rule TTP_XOR_MULT_DOSStub_622f {
  strings:
    $key_622f = { 36 47 [2] 42 5f [2] 05 5d [2] 42 4c [2] 0c 40 [2] 00 4a [2] 17 41 [2] 0c 0f [2] 31 }

  condition:
    any of them
}