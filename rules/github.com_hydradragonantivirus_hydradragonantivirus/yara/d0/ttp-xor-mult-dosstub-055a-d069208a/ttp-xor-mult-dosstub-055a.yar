rule TTP_XOR_MULT_DOSStub_055a {
  strings:
    $key_055a = { 51 32 [2] 25 2a [2] 62 28 [2] 25 39 [2] 6b 35 [2] 67 3f [2] 70 34 [2] 6b 7a [2] 56 }

  condition:
    any of them
}