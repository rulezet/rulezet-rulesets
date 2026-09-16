rule TTP_XOR_MULT_DOSStub_586f {
  strings:
    $key_586f = { 0c 07 [2] 78 1f [2] 3f 1d [2] 78 0c [2] 36 00 [2] 3a 0a [2] 2d 01 [2] 36 4f [2] 0b }

  condition:
    any of them
}