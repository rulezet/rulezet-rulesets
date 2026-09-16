rule TTP_XOR_MULT_DOSStub_c72b {
  strings:
    $key_c72b = { 93 43 [2] e7 5b [2] a0 59 [2] e7 48 [2] a9 44 [2] a5 4e [2] b2 45 [2] a9 0b [2] 94 }

  condition:
    any of them
}