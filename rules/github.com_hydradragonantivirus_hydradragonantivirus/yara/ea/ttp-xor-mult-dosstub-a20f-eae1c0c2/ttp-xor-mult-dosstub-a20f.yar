rule TTP_XOR_MULT_DOSStub_a20f {
  strings:
    $key_a20f = { f6 67 [2] 82 7f [2] c5 7d [2] 82 6c [2] cc 60 [2] c0 6a [2] d7 61 [2] cc 2f [2] f1 }

  condition:
    any of them
}