rule TTP_XOR_MULT_DOSStub_57e1 {
  strings:
    $key_57e1 = { 03 89 [2] 77 91 [2] 30 93 [2] 77 82 [2] 39 8e [2] 35 84 [2] 22 8f [2] 39 c1 [2] 04 }

  condition:
    any of them
}