rule TTP_XOR_MULT_DOSStub_377a {
  strings:
    $key_377a = { 63 12 [2] 17 0a [2] 50 08 [2] 17 19 [2] 59 15 [2] 55 1f [2] 42 14 [2] 59 5a [2] 64 }

  condition:
    any of them
}