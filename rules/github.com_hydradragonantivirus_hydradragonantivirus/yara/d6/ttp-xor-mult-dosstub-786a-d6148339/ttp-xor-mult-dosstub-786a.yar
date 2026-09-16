rule TTP_XOR_MULT_DOSStub_786a {
  strings:
    $key_786a = { 2c 02 [2] 58 1a [2] 1f 18 [2] 58 09 [2] 16 05 [2] 1a 0f [2] 0d 04 [2] 16 4a [2] 2b }

  condition:
    any of them
}