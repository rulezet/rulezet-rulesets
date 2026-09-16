rule TTP_XOR_MULT_DOSStub_290a {
  strings:
    $key_290a = { 7d 62 [2] 09 7a [2] 4e 78 [2] 09 69 [2] 47 65 [2] 4b 6f [2] 5c 64 [2] 47 2a [2] 7a }

  condition:
    any of them
}