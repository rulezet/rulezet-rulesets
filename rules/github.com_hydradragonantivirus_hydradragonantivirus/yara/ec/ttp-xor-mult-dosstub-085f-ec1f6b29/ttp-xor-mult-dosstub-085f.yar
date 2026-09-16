rule TTP_XOR_MULT_DOSStub_085f {
  strings:
    $key_085f = { 5c 37 [2] 28 2f [2] 6f 2d [2] 28 3c [2] 66 30 [2] 6a 3a [2] 7d 31 [2] 66 7f [2] 5b }

  condition:
    any of them
}