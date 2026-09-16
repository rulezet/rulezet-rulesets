rule TTP_XOR_MULT_DOSStub_723a {
  strings:
    $key_723a = { 26 52 [2] 52 4a [2] 15 48 [2] 52 59 [2] 1c 55 [2] 10 5f [2] 07 54 [2] 1c 1a [2] 21 }

  condition:
    any of them
}