rule TTP_XOR_MULT_DOSStub_4dea {
  strings:
    $key_4dea = { 19 82 [2] 6d 9a [2] 2a 98 [2] 6d 89 [2] 23 85 [2] 2f 8f [2] 38 84 [2] 23 ca [2] 1e }

  condition:
    any of them
}