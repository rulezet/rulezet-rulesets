rule TTP_XOR_MULT_DOSStub_5e2a {
  strings:
    $key_5e2a = { 0a 42 [2] 7e 5a [2] 39 58 [2] 7e 49 [2] 30 45 [2] 3c 4f [2] 2b 44 [2] 30 0a [2] 0d }

  condition:
    any of them
}