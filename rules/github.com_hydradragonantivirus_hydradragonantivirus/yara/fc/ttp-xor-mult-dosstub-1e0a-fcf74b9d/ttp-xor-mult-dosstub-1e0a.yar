rule TTP_XOR_MULT_DOSStub_1e0a {
  strings:
    $key_1e0a = { 4a 62 [2] 3e 7a [2] 79 78 [2] 3e 69 [2] 70 65 [2] 7c 6f [2] 6b 64 [2] 70 2a [2] 4d }

  condition:
    any of them
}