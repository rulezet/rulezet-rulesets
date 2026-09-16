rule TTP_XOR_MULT_DOSStub_315b {
  strings:
    $key_315b = { 65 33 [2] 11 2b [2] 56 29 [2] 11 38 [2] 5f 34 [2] 53 3e [2] 44 35 [2] 5f 7b [2] 62 }

  condition:
    any of them
}