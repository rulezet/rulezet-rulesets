rule TTP_XOR_MULT_DOSStub_75ea {
  strings:
    $key_75ea = { 21 82 [2] 55 9a [2] 12 98 [2] 55 89 [2] 1b 85 [2] 17 8f [2] 00 84 [2] 1b ca [2] 26 }

  condition:
    any of them
}