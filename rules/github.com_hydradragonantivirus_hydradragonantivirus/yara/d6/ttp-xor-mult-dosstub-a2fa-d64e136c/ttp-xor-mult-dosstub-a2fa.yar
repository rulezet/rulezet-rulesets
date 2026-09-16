rule TTP_XOR_MULT_DOSStub_a2fa {
  strings:
    $key_a2fa = { f6 92 [2] 82 8a [2] c5 88 [2] 82 99 [2] cc 95 [2] c0 9f [2] d7 94 [2] cc da [2] f1 }

  condition:
    any of them
}