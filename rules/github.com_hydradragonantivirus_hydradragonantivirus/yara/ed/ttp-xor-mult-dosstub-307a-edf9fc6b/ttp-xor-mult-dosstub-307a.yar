rule TTP_XOR_MULT_DOSStub_307a {
  strings:
    $key_307a = { 64 12 [2] 10 0a [2] 57 08 [2] 10 19 [2] 5e 15 [2] 52 1f [2] 45 14 [2] 5e 5a [2] 63 }

  condition:
    any of them
}