rule TTP_XOR_MULT_DOSStub_7869 {
  strings:
    $key_7869 = { 2c 01 [2] 58 19 [2] 1f 1b [2] 58 0a [2] 16 06 [2] 1a 0c [2] 0d 07 [2] 16 49 [2] 2b }

  condition:
    any of them
}