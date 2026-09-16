rule TTP_XOR_MULT_DOSStub_221f {
  strings:
    $key_221f = { 76 77 [2] 02 6f [2] 45 6d [2] 02 7c [2] 4c 70 [2] 40 7a [2] 57 71 [2] 4c 3f [2] 71 }

  condition:
    any of them
}