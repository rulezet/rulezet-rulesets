rule TTP_XOR_MULT_DOSStub_167b {
  strings:
    $key_167b = { 42 13 [2] 36 0b [2] 71 09 [2] 36 18 [2] 78 14 [2] 74 1e [2] 63 15 [2] 78 5b [2] 45 }

  condition:
    any of them
}