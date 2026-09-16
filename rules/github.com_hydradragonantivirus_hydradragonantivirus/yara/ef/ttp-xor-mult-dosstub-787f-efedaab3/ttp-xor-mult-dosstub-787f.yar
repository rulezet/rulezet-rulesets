rule TTP_XOR_MULT_DOSStub_787f {
  strings:
    $key_787f = { 2c 17 [2] 58 0f [2] 1f 0d [2] 58 1c [2] 16 10 [2] 1a 1a [2] 0d 11 [2] 16 5f [2] 2b }

  condition:
    any of them
}