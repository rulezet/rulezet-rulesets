rule TTP_XOR_MULT_DOSStub_a467 {
  strings:
    $key_a467 = { f0 0f [2] 84 17 [2] c3 15 [2] 84 04 [2] ca 08 [2] c6 02 [2] d1 09 [2] ca 47 [2] f7 }

  condition:
    any of them
}