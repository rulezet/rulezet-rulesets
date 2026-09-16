rule TTP_XOR_MULT_DOSStub_750f {
  strings:
    $key_750f = { 21 67 [2] 55 7f [2] 12 7d [2] 55 6c [2] 1b 60 [2] 17 6a [2] 00 61 [2] 1b 2f [2] 26 }

  condition:
    any of them
}