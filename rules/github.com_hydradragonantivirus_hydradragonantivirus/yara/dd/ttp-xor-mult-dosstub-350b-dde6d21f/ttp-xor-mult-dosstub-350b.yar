rule TTP_XOR_MULT_DOSStub_350b {
  strings:
    $key_350b = { 61 63 [2] 15 7b [2] 52 79 [2] 15 68 [2] 5b 64 [2] 57 6e [2] 40 65 [2] 5b 2b [2] 66 }

  condition:
    any of them
}