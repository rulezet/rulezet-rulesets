rule TTP_XOR_MULT_DOSStub_6b4b {
  strings:
    $key_6b4b = { 3f 23 [2] 4b 3b [2] 0c 39 [2] 4b 28 [2] 05 24 [2] 09 2e [2] 1e 25 [2] 05 6b [2] 38 }

  condition:
    any of them
}