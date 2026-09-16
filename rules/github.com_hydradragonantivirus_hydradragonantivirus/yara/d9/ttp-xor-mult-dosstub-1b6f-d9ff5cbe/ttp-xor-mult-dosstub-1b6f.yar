rule TTP_XOR_MULT_DOSStub_1b6f {
  strings:
    $key_1b6f = { 4f 07 [2] 3b 1f [2] 7c 1d [2] 3b 0c [2] 75 00 [2] 79 0a [2] 6e 01 [2] 75 4f [2] 48 }

  condition:
    any of them
}