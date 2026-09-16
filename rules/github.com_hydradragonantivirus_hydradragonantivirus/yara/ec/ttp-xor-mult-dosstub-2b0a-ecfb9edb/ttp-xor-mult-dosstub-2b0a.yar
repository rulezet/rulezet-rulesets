rule TTP_XOR_MULT_DOSStub_2b0a {
  strings:
    $key_2b0a = { 7f 62 [2] 0b 7a [2] 4c 78 [2] 0b 69 [2] 45 65 [2] 49 6f [2] 5e 64 [2] 45 2a [2] 78 }

  condition:
    any of them
}