rule TTP_XOR_MULT_DOSStub_571b {
  strings:
    $key_571b = { 03 73 [2] 77 6b [2] 30 69 [2] 77 78 [2] 39 74 [2] 35 7e [2] 22 75 [2] 39 3b [2] 04 }

  condition:
    any of them
}