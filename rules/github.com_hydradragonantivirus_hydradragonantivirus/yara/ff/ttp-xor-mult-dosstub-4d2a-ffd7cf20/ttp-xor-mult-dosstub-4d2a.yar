rule TTP_XOR_MULT_DOSStub_4d2a {
  strings:
    $key_4d2a = { 19 42 [2] 6d 5a [2] 2a 58 [2] 6d 49 [2] 23 45 [2] 2f 4f [2] 38 44 [2] 23 0a [2] 1e }

  condition:
    any of them
}