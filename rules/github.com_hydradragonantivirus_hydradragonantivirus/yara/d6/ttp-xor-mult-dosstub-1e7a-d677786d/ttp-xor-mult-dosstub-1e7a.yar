rule TTP_XOR_MULT_DOSStub_1e7a {
  strings:
    $key_1e7a = { 4a 12 [2] 3e 0a [2] 79 08 [2] 3e 19 [2] 70 15 [2] 7c 1f [2] 6b 14 [2] 70 5a [2] 4d }

  condition:
    any of them
}