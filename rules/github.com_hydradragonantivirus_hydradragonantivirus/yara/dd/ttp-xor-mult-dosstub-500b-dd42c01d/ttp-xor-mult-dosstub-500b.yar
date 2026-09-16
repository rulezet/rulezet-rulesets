rule TTP_XOR_MULT_DOSStub_500b {
  strings:
    $key_500b = { 04 63 [2] 70 7b [2] 37 79 [2] 70 68 [2] 3e 64 [2] 32 6e [2] 25 65 [2] 3e 2b [2] 03 }

  condition:
    any of them
}