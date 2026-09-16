rule TTP_XOR_MULT_DOSStub_595a {
  strings:
    $key_595a = { 0d 32 [2] 79 2a [2] 3e 28 [2] 79 39 [2] 37 35 [2] 3b 3f [2] 2c 34 [2] 37 7a [2] 0a }

  condition:
    any of them
}