rule TTP_XOR_MULT_DOSStub_15fa {
  strings:
    $key_15fa = { 41 92 [2] 35 8a [2] 72 88 [2] 35 99 [2] 7b 95 [2] 77 9f [2] 60 94 [2] 7b da [2] 46 }

  condition:
    any of them
}