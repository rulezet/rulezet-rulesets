rule TTP_XOR_MULT_DOSStub_2e5a {
  strings:
    $key_2e5a = { 7a 32 [2] 0e 2a [2] 49 28 [2] 0e 39 [2] 40 35 [2] 4c 3f [2] 5b 34 [2] 40 7a [2] 7d }

  condition:
    any of them
}