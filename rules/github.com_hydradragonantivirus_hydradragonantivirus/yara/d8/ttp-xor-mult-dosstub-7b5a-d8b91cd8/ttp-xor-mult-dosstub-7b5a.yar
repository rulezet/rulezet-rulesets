rule TTP_XOR_MULT_DOSStub_7b5a {
  strings:
    $key_7b5a = { 2f 32 [2] 5b 2a [2] 1c 28 [2] 5b 39 [2] 15 35 [2] 19 3f [2] 0e 34 [2] 15 7a [2] 28 }

  condition:
    any of them
}