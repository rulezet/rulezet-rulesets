rule TTP_XOR_MULT_DOSStub_6a5a {
  strings:
    $key_6a5a = { 3e 32 [2] 4a 2a [2] 0d 28 [2] 4a 39 [2] 04 35 [2] 08 3f [2] 1f 34 [2] 04 7a [2] 39 }

  condition:
    any of them
}