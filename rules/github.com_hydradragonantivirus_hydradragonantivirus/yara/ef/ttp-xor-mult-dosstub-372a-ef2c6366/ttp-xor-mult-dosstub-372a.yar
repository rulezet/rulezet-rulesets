rule TTP_XOR_MULT_DOSStub_372a {
  strings:
    $key_372a = { 63 42 [2] 17 5a [2] 50 58 [2] 17 49 [2] 59 45 [2] 55 4f [2] 42 44 [2] 59 0a [2] 64 }

  condition:
    any of them
}