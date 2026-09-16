rule TTP_XOR_MULT_DOSStub_c03b {
  strings:
    $key_c03b = { 94 53 [2] e0 4b [2] a7 49 [2] e0 58 [2] ae 54 [2] a2 5e [2] b5 55 [2] ae 1b [2] 93 }

  condition:
    any of them
}