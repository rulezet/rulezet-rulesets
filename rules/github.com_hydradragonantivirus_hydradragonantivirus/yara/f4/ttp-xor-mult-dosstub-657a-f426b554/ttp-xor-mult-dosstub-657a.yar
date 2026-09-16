rule TTP_XOR_MULT_DOSStub_657a {
  strings:
    $key_657a = { 31 12 [2] 45 0a [2] 02 08 [2] 45 19 [2] 0b 15 [2] 07 1f [2] 10 14 [2] 0b 5a [2] 36 }

  condition:
    any of them
}