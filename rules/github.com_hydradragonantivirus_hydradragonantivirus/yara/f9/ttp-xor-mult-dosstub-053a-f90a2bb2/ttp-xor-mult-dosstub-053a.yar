rule TTP_XOR_MULT_DOSStub_053a {
  strings:
    $key_053a = { 51 52 [2] 25 4a [2] 62 48 [2] 25 59 [2] 6b 55 [2] 67 5f [2] 70 54 [2] 6b 1a [2] 56 }

  condition:
    any of them
}