rule TTP_XOR_MULT_DOSStub_166b {
  strings:
    $key_166b = { 42 03 [2] 36 1b [2] 71 19 [2] 36 08 [2] 78 04 [2] 74 0e [2] 63 05 [2] 78 4b [2] 45 }

  condition:
    any of them
}