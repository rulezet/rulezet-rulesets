rule TTP_XOR_MULT_DOSStub_7d6b {
  strings:
    $key_7d6b = { 29 03 [2] 5d 1b [2] 1a 19 [2] 5d 08 [2] 13 04 [2] 1f 0e [2] 08 05 [2] 13 4b [2] 2e }

  condition:
    any of them
}