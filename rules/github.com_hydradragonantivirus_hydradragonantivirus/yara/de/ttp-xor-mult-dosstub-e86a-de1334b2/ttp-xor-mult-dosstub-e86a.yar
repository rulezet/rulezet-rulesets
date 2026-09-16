rule TTP_XOR_MULT_DOSStub_e86a {
  strings:
    $key_e86a = { bc 02 [2] c8 1a [2] 8f 18 [2] c8 09 [2] 86 05 [2] 8a 0f [2] 9d 04 [2] 86 4a [2] bb }

  condition:
    any of them
}