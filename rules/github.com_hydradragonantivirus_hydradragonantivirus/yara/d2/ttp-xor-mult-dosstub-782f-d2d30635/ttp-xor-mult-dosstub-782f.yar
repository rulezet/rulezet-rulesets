rule TTP_XOR_MULT_DOSStub_782f {
  strings:
    $key_782f = { 2c 47 [2] 58 5f [2] 1f 5d [2] 58 4c [2] 16 40 [2] 1a 4a [2] 0d 41 [2] 16 0f [2] 2b }

  condition:
    any of them
}