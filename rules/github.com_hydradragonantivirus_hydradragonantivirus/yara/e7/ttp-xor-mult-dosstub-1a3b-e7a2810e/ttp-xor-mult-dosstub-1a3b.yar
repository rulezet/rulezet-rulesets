rule TTP_XOR_MULT_DOSStub_1a3b {
  strings:
    $key_1a3b = { 4e 53 [2] 3a 4b [2] 7d 49 [2] 3a 58 [2] 74 54 [2] 78 5e [2] 6f 55 [2] 74 1b [2] 49 }

  condition:
    any of them
}