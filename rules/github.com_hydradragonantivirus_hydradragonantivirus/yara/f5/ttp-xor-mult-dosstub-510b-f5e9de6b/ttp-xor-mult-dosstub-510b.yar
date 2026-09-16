rule TTP_XOR_MULT_DOSStub_510b {
  strings:
    $key_510b = { 05 63 [2] 71 7b [2] 36 79 [2] 71 68 [2] 3f 64 [2] 33 6e [2] 24 65 [2] 3f 2b [2] 02 }

  condition:
    any of them
}