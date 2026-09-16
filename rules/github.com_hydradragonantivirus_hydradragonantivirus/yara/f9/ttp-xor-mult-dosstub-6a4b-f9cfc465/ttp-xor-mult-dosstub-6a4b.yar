rule TTP_XOR_MULT_DOSStub_6a4b {
  strings:
    $key_6a4b = { 3e 23 [2] 4a 3b [2] 0d 39 [2] 4a 28 [2] 04 24 [2] 08 2e [2] 1f 25 [2] 04 6b [2] 39 }

  condition:
    any of them
}