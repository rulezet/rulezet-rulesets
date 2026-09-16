rule TTP_XOR_MULT_DOSStub_3e48 {
  strings:
    $key_3e48 = { 6a 20 [2] 1e 38 [2] 59 3a [2] 1e 2b [2] 50 27 [2] 5c 2d [2] 4b 26 [2] 50 68 [2] 6d }

  condition:
    any of them
}