rule TTP_XOR_MULT_DOSStub_256b {
  strings:
    $key_256b = { 71 03 [2] 05 1b [2] 42 19 [2] 05 08 [2] 4b 04 [2] 47 0e [2] 50 05 [2] 4b 4b [2] 76 }

  condition:
    any of them
}