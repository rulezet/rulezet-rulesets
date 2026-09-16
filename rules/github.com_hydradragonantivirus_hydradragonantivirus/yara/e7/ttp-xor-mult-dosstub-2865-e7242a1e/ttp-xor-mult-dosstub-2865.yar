rule TTP_XOR_MULT_DOSStub_2865 {
  strings:
    $key_2865 = { 7c 0d [2] 08 15 [2] 4f 17 [2] 08 06 [2] 46 0a [2] 4a 00 [2] 5d 0b [2] 46 45 [2] 7b }

  condition:
    any of them
}