rule TTP_XOR_MULT_DOSStub_400a {
  strings:
    $key_400a = { 14 62 [2] 60 7a [2] 27 78 [2] 60 69 [2] 2e 65 [2] 22 6f [2] 35 64 [2] 2e 2a [2] 13 }

  condition:
    any of them
}