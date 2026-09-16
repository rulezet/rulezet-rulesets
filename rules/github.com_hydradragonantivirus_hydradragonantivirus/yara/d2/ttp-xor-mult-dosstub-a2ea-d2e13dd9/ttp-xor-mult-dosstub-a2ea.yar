rule TTP_XOR_MULT_DOSStub_a2ea {
  strings:
    $key_a2ea = { f6 82 [2] 82 9a [2] c5 98 [2] 82 89 [2] cc 85 [2] c0 8f [2] d7 84 [2] cc ca [2] f1 }

  condition:
    any of them
}