rule TTP_XOR_MULT_DOSStub_700a {
  strings:
    $key_700a = { 24 62 [2] 50 7a [2] 17 78 [2] 50 69 [2] 1e 65 [2] 12 6f [2] 05 64 [2] 1e 2a [2] 23 }

  condition:
    any of them
}