rule TTP_XOR_MULT_DOSStub_4d7a {
  strings:
    $key_4d7a = { 19 12 [2] 6d 0a [2] 2a 08 [2] 6d 19 [2] 23 15 [2] 2f 1f [2] 38 14 [2] 23 5a [2] 1e }

  condition:
    any of them
}