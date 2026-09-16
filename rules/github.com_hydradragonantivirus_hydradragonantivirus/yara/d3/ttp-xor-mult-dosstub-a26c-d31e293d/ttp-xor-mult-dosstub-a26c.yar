rule TTP_XOR_MULT_DOSStub_a26c {
  strings:
    $key_a26c = { f6 04 [2] 82 1c [2] c5 1e [2] 82 0f [2] cc 03 [2] c0 09 [2] d7 02 [2] cc 4c [2] f1 }

  condition:
    any of them
}