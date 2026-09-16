rule TTP_XOR_MULT_DOSStub_795a {
  strings:
    $key_795a = { 2d 32 [2] 59 2a [2] 1e 28 [2] 59 39 [2] 17 35 [2] 1b 3f [2] 0c 34 [2] 17 7a [2] 2a }

  condition:
    any of them
}