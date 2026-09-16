rule TTP_XOR_MULT_DOSStub_187f {
  strings:
    $key_187f = { 4c 17 [2] 38 0f [2] 7f 0d [2] 38 1c [2] 76 10 [2] 7a 1a [2] 6d 11 [2] 76 5f [2] 4b }

  condition:
    any of them
}