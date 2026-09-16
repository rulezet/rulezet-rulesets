rule TTP_XOR_MULT_DOSStub_070a {
  strings:
    $key_070a = { 53 62 [2] 27 7a [2] 60 78 [2] 27 69 [2] 69 65 [2] 65 6f [2] 72 64 [2] 69 2a [2] 54 }

  condition:
    any of them
}