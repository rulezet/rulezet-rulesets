rule TTP_XOR_MULT_DOSStub_057a {
  strings:
    $key_057a = { 51 12 [2] 25 0a [2] 62 08 [2] 25 19 [2] 6b 15 [2] 67 1f [2] 70 14 [2] 6b 5a [2] 56 }

  condition:
    any of them
}