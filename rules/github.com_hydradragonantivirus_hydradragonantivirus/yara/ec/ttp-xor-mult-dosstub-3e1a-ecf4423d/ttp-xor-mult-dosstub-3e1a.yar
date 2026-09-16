rule TTP_XOR_MULT_DOSStub_3e1a {
  strings:
    $key_3e1a = { 6a 72 [2] 1e 6a [2] 59 68 [2] 1e 79 [2] 50 75 [2] 5c 7f [2] 4b 74 [2] 50 3a [2] 6d }

  condition:
    any of them
}