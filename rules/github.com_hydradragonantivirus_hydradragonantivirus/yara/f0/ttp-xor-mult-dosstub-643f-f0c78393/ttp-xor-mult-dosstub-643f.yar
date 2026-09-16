rule TTP_XOR_MULT_DOSStub_643f {
  strings:
    $key_643f = { 30 57 [2] 44 4f [2] 03 4d [2] 44 5c [2] 0a 50 [2] 06 5a [2] 11 51 [2] 0a 1f [2] 37 }

  condition:
    any of them
}