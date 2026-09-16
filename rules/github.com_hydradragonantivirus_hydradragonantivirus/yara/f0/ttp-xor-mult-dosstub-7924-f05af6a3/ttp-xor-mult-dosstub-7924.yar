rule TTP_XOR_MULT_DOSStub_7924 {
  strings:
    $key_7924 = { 2d 4c [2] 59 54 [2] 1e 56 [2] 59 47 [2] 17 4b [2] 1b 41 [2] 0c 4a [2] 17 04 [2] 2a }

  condition:
    any of them
}