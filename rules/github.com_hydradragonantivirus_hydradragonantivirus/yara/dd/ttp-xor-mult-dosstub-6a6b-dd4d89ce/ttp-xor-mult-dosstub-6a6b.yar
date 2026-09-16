rule TTP_XOR_MULT_DOSStub_6a6b {
  strings:
    $key_6a6b = { 3e 03 [2] 4a 1b [2] 0d 19 [2] 4a 08 [2] 04 04 [2] 08 0e [2] 1f 05 [2] 04 4b [2] 39 }

  condition:
    any of them
}