rule TTP_XOR_MULT_DOSStub_373a {
  strings:
    $key_373a = { 63 52 [2] 17 4a [2] 50 48 [2] 17 59 [2] 59 55 [2] 55 5f [2] 42 54 [2] 59 1a [2] 64 }

  condition:
    any of them
}