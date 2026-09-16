rule TTP_XOR_MULT_DOSStub_6e5a {
  strings:
    $key_6e5a = { 3a 32 [2] 4e 2a [2] 09 28 [2] 4e 39 [2] 00 35 [2] 0c 3f [2] 1b 34 [2] 00 7a [2] 3d }

  condition:
    any of them
}