rule TTP_XOR_MULT_DOSStub_756f {
  strings:
    $key_756f = { 21 07 [2] 55 1f [2] 12 1d [2] 55 0c [2] 1b 00 [2] 17 0a [2] 00 01 [2] 1b 4f [2] 26 }

  condition:
    any of them
}