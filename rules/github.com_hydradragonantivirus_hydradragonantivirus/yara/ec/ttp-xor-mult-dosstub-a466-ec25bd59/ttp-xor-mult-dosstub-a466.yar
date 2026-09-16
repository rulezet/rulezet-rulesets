rule TTP_XOR_MULT_DOSStub_a466 {
  strings:
    $key_a466 = { f0 0e [2] 84 16 [2] c3 14 [2] 84 05 [2] ca 09 [2] c6 03 [2] d1 08 [2] ca 46 [2] f7 }

  condition:
    any of them
}