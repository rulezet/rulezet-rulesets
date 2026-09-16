rule TTP_XOR_MULT_DOSStub_167c {
  strings:
    $key_167c = { 42 14 [2] 36 0c [2] 71 0e [2] 36 1f [2] 78 13 [2] 74 19 [2] 63 12 [2] 78 5c [2] 45 }

  condition:
    any of them
}