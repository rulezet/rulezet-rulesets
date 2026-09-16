rule TTP_XOR_MULT_DOSStub_1f5a {
  strings:
    $key_1f5a = { 4b 32 [2] 3f 2a [2] 78 28 [2] 3f 39 [2] 71 35 [2] 7d 3f [2] 6a 34 [2] 71 7a [2] 4c }

  condition:
    any of them
}