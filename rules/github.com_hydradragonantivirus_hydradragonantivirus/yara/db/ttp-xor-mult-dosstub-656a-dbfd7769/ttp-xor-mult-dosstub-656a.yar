rule TTP_XOR_MULT_DOSStub_656a {
  strings:
    $key_656a = { 31 02 [2] 45 1a [2] 02 18 [2] 45 09 [2] 0b 05 [2] 07 0f [2] 10 04 [2] 0b 4a [2] 36 }

  condition:
    any of them
}