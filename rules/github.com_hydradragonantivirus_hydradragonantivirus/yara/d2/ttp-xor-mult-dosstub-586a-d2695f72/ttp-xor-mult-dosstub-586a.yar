rule TTP_XOR_MULT_DOSStub_586a {
  strings:
    $key_586a = { 0c 02 [2] 78 1a [2] 3f 18 [2] 78 09 [2] 36 05 [2] 3a 0f [2] 2d 04 [2] 36 4a [2] 0b }

  condition:
    any of them
}