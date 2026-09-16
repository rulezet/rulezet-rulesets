rule TTP_XOR_MULT_DOSStub_114b {
  strings:
    $key_114b = { 45 23 [2] 31 3b [2] 76 39 [2] 31 28 [2] 7f 24 [2] 73 2e [2] 64 25 [2] 7f 6b [2] 42 }

  condition:
    any of them
}