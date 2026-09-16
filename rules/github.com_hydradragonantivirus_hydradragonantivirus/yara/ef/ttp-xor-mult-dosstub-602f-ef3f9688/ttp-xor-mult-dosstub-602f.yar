rule TTP_XOR_MULT_DOSStub_602f {
  strings:
    $key_602f = { 34 47 [2] 40 5f [2] 07 5d [2] 40 4c [2] 0e 40 [2] 02 4a [2] 15 41 [2] 0e 0f [2] 33 }

  condition:
    any of them
}