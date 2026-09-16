rule TTP_XOR_MULT_DOSStub_236b {
  strings:
    $key_236b = { 77 03 [2] 03 1b [2] 44 19 [2] 03 08 [2] 4d 04 [2] 41 0e [2] 56 05 [2] 4d 4b [2] 70 }

  condition:
    any of them
}