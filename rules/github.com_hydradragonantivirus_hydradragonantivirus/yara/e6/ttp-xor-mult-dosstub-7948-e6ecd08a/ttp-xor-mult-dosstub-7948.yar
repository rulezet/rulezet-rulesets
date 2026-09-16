rule TTP_XOR_MULT_DOSStub_7948 {
  strings:
    $key_7948 = { 2d 20 [2] 59 38 [2] 1e 3a [2] 59 2b [2] 17 27 [2] 1b 2d [2] 0c 26 [2] 17 68 [2] 2a }

  condition:
    any of them
}