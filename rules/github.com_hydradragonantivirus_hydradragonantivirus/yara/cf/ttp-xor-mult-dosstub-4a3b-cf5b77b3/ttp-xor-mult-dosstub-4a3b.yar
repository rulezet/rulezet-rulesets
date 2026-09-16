rule TTP_XOR_MULT_DOSStub_4a3b {
  strings:
    $key_4a3b = { 1e 53 [2] 6a 4b [2] 2d 49 [2] 6a 58 [2] 24 54 [2] 28 5e [2] 3f 55 [2] 24 1b [2] 19 }

  condition:
    any of them
}