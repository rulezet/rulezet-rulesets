rule TTP_XOR_MULT_DOSStub_25fa {
  strings:
    $key_25fa = { 71 92 [2] 05 8a [2] 42 88 [2] 05 99 [2] 4b 95 [2] 47 9f [2] 50 94 [2] 4b da [2] 76 }

  condition:
    any of them
}