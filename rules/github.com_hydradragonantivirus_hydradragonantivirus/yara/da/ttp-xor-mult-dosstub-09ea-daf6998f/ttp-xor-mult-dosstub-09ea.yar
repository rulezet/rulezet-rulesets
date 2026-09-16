rule TTP_XOR_MULT_DOSStub_09ea {
  strings:
    $key_09ea = { 5d 82 [2] 29 9a [2] 6e 98 [2] 29 89 [2] 67 85 [2] 6b 8f [2] 7c 84 [2] 67 ca [2] 5a }

  condition:
    any of them
}