rule TTP_XOR_MULT_DOSStub_3b3a {
  strings:
    $key_3b3a = { 6f 52 [2] 1b 4a [2] 5c 48 [2] 1b 59 [2] 55 55 [2] 59 5f [2] 4e 54 [2] 55 1a [2] 68 }

  condition:
    any of them
}