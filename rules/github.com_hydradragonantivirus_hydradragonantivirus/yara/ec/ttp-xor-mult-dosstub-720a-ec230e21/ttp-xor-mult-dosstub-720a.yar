rule TTP_XOR_MULT_DOSStub_720a {
  strings:
    $key_720a = { 26 62 [2] 52 7a [2] 15 78 [2] 52 69 [2] 1c 65 [2] 10 6f [2] 07 64 [2] 1c 2a [2] 21 }

  condition:
    any of them
}