rule TTP_XOR_MULT_DOSStub_7e0a {
  strings:
    $key_7e0a = { 2a 62 [2] 5e 7a [2] 19 78 [2] 5e 69 [2] 10 65 [2] 1c 6f [2] 0b 64 [2] 10 2a [2] 2d }

  condition:
    any of them
}