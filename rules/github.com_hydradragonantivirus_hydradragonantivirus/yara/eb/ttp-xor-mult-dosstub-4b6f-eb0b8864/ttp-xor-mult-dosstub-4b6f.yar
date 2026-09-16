rule TTP_XOR_MULT_DOSStub_4b6f {
  strings:
    $key_4b6f = { 1f 07 [2] 6b 1f [2] 2c 1d [2] 6b 0c [2] 25 00 [2] 29 0a [2] 3e 01 [2] 25 4f [2] 18 }

  condition:
    any of them
}