rule TTP_XOR_MULT_DOSStub_222f {
  strings:
    $key_222f = { 76 47 [2] 02 5f [2] 45 5d [2] 02 4c [2] 4c 40 [2] 40 4a [2] 57 41 [2] 4c 0f [2] 71 }

  condition:
    any of them
}