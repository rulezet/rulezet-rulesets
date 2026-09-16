rule TTP_XOR_MULT_DOSStub_2e0a {
  strings:
    $key_2e0a = { 7a 62 [2] 0e 7a [2] 49 78 [2] 0e 69 [2] 40 65 [2] 4c 6f [2] 5b 64 [2] 40 2a [2] 7d }

  condition:
    any of them
}