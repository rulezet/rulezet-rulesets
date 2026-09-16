rule TTP_XOR_MULT_DOSStub_4b65 {
  strings:
    $key_4b65 = { 1f 0d [2] 6b 15 [2] 2c 17 [2] 6b 06 [2] 25 0a [2] 29 00 [2] 3e 0b [2] 25 45 [2] 18 }

  condition:
    any of them
}