rule TTP_XOR_MULT_DOSStub_3aea {
  strings:
    $key_3aea = { 6e 82 [2] 1a 9a [2] 5d 98 [2] 1a 89 [2] 54 85 [2] 58 8f [2] 4f 84 [2] 54 ca [2] 69 }

  condition:
    any of them
}