rule TTP_XOR_MULT_DOSStub_5b0a {
  strings:
    $key_5b0a = { 0f 62 [2] 7b 7a [2] 3c 78 [2] 7b 69 [2] 35 65 [2] 39 6f [2] 2e 64 [2] 35 2a [2] 08 }

  condition:
    any of them
}