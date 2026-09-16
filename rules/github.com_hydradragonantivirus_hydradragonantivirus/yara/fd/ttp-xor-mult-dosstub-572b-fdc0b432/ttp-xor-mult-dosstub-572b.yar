rule TTP_XOR_MULT_DOSStub_572b {
  strings:
    $key_572b = { 03 43 [2] 77 5b [2] 30 59 [2] 77 48 [2] 39 44 [2] 35 4e [2] 22 45 [2] 39 0b [2] 04 }

  condition:
    any of them
}