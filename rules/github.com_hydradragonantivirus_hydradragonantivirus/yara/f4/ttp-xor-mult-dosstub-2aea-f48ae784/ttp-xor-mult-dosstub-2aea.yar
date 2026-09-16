rule TTP_XOR_MULT_DOSStub_2aea {
  strings:
    $key_2aea = { 7e 82 [2] 0a 9a [2] 4d 98 [2] 0a 89 [2] 44 85 [2] 48 8f [2] 5f 84 [2] 44 ca [2] 79 }

  condition:
    any of them
}