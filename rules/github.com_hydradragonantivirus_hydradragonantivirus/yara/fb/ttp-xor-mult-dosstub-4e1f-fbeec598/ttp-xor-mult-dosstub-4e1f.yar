rule TTP_XOR_MULT_DOSStub_4e1f {
  strings:
    $key_4e1f = { 1a 77 [2] 6e 6f [2] 29 6d [2] 6e 7c [2] 20 70 [2] 2c 7a [2] 3b 71 [2] 20 3f [2] 1d }

  condition:
    any of them
}