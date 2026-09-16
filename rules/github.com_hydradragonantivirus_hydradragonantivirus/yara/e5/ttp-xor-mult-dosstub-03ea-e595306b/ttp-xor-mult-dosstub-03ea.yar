rule TTP_XOR_MULT_DOSStub_03ea {
  strings:
    $key_03ea = { 57 82 [2] 23 9a [2] 64 98 [2] 23 89 [2] 6d 85 [2] 61 8f [2] 76 84 [2] 6d ca [2] 50 }

  condition:
    any of them
}