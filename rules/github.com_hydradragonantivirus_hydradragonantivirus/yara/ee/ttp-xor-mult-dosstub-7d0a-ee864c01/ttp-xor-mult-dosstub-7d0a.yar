rule TTP_XOR_MULT_DOSStub_7d0a {
  strings:
    $key_7d0a = { 29 62 [2] 5d 7a [2] 1a 78 [2] 5d 69 [2] 13 65 [2] 1f 6f [2] 08 64 [2] 13 2a [2] 2e }

  condition:
    any of them
}