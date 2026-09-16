rule TTP_XOR_MULT_DOSStub_500a {
  strings:
    $key_500a = { 04 62 [2] 70 7a [2] 37 78 [2] 70 69 [2] 3e 65 [2] 32 6f [2] 25 64 [2] 3e 2a [2] 03 }

  condition:
    any of them
}