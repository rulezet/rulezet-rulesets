rule TTP_XOR_MULT_DOSStub_085a {
  strings:
    $key_085a = { 5c 32 [2] 28 2a [2] 6f 28 [2] 28 39 [2] 66 35 [2] 6a 3f [2] 7d 34 [2] 66 7a [2] 5b }

  condition:
    any of them
}