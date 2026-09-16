rule TTP_XOR_MULT_DOSStub_57e0 {
  strings:
    $key_57e0 = { 03 88 [2] 77 90 [2] 30 92 [2] 77 83 [2] 39 8f [2] 35 85 [2] 22 8e [2] 39 c0 [2] 04 }

  condition:
    any of them
}