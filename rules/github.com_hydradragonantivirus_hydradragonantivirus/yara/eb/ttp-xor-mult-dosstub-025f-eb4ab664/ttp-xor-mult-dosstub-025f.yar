rule TTP_XOR_MULT_DOSStub_025f {
  strings:
    $key_025f = { 56 37 [2] 22 2f [2] 65 2d [2] 22 3c [2] 6c 30 [2] 60 3a [2] 77 31 [2] 6c 7f [2] 51 }

  condition:
    any of them
}