rule TTP_XOR_MULT_DOSStub_202a {
  strings:
    $key_202a = { 74 42 [2] 00 5a [2] 47 58 [2] 00 49 [2] 4e 45 [2] 42 4f [2] 55 44 [2] 4e 0a [2] 73 }

  condition:
    any of them
}