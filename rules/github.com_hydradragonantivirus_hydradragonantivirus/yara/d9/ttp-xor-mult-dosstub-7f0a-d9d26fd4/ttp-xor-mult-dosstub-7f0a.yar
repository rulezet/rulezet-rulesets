rule TTP_XOR_MULT_DOSStub_7f0a {
  strings:
    $key_7f0a = { 2b 62 [2] 5f 7a [2] 18 78 [2] 5f 69 [2] 11 65 [2] 1d 6f [2] 0a 64 [2] 11 2a [2] 2c }

  condition:
    any of them
}