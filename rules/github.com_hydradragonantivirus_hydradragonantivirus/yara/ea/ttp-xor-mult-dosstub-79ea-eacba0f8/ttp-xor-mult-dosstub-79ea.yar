rule TTP_XOR_MULT_DOSStub_79ea {
  strings:
    $key_79ea = { 2d 82 [2] 59 9a [2] 1e 98 [2] 59 89 [2] 17 85 [2] 1b 8f [2] 0c 84 [2] 17 ca [2] 2a }

  condition:
    any of them
}