rule TTP_XOR_MULT_DOSStub_797a {
  strings:
    $key_797a = { 2d 12 [2] 59 0a [2] 1e 08 [2] 59 19 [2] 17 15 [2] 1b 1f [2] 0c 14 [2] 17 5a [2] 2a }

  condition:
    any of them
}