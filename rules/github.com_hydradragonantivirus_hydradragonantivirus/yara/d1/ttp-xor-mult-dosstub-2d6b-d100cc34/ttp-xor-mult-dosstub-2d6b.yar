rule TTP_XOR_MULT_DOSStub_2d6b {
  strings:
    $key_2d6b = { 79 03 [2] 0d 1b [2] 4a 19 [2] 0d 08 [2] 43 04 [2] 4f 0e [2] 58 05 [2] 43 4b [2] 7e }

  condition:
    any of them
}