rule TTP_XOR_MULT_DOSStub_1aea {
  strings:
    $key_1aea = { 4e 82 [2] 3a 9a [2] 7d 98 [2] 3a 89 [2] 74 85 [2] 78 8f [2] 6f 84 [2] 74 ca [2] 49 }

  condition:
    any of them
}