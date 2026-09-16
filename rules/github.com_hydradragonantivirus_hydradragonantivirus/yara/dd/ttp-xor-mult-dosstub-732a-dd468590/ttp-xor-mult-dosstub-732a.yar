rule TTP_XOR_MULT_DOSStub_732a {
  strings:
    $key_732a = { 27 42 [2] 53 5a [2] 14 58 [2] 53 49 [2] 1d 45 [2] 11 4f [2] 06 44 [2] 1d 0a [2] 20 }

  condition:
    any of them
}