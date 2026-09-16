rule TTP_XOR_MULT_DOSStub_5e55 {
  strings:
    $key_5e55 = { 0a 3d [2] 7e 25 [2] 39 27 [2] 7e 36 [2] 30 3a [2] 3c 30 [2] 2b 3b [2] 30 75 [2] 0d }

  condition:
    any of them
}