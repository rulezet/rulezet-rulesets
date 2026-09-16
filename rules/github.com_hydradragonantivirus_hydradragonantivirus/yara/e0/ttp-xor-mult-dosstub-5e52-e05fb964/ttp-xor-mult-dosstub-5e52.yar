rule TTP_XOR_MULT_DOSStub_5e52 {
  strings:
    $key_5e52 = { 0a 3a [2] 7e 22 [2] 39 20 [2] 7e 31 [2] 30 3d [2] 3c 37 [2] 2b 3c [2] 30 72 [2] 0d }

  condition:
    any of them
}