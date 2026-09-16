rule TTP_XOR_MULT_DOSStub_3b4b {
  strings:
    $key_3b4b = { 6f 23 [2] 1b 3b [2] 5c 39 [2] 1b 28 [2] 55 24 [2] 59 2e [2] 4e 25 [2] 55 6b [2] 68 }

  condition:
    any of them
}