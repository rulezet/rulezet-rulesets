rule TTP_XOR_MULT_DOSStub_136b {
  strings:
    $key_136b = { 47 03 [2] 33 1b [2] 74 19 [2] 33 08 [2] 7d 04 [2] 71 0e [2] 66 05 [2] 7d 4b [2] 40 }

  condition:
    any of them
}