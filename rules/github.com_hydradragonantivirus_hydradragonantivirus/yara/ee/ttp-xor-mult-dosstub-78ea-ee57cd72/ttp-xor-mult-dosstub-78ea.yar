rule TTP_XOR_MULT_DOSStub_78ea {
  strings:
    $key_78ea = { 2c 82 [2] 58 9a [2] 1f 98 [2] 58 89 [2] 16 85 [2] 1a 8f [2] 0d 84 [2] 16 ca [2] 2b }

  condition:
    any of them
}