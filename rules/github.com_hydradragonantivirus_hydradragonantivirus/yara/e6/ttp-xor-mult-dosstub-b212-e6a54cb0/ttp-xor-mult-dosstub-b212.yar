rule TTP_XOR_MULT_DOSStub_b212 {
  strings:
    $key_b212 = { e6 7a [2] 92 62 [2] d5 60 [2] 92 71 [2] dc 7d [2] d0 77 [2] c7 7c [2] dc 32 [2] e1 }

  condition:
    any of them
}