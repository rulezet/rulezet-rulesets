rule TTP_XOR_MULT_DOSStub_a40a {
  strings:
    $key_a40a = { f0 62 [2] 84 7a [2] c3 78 [2] 84 69 [2] ca 65 [2] c6 6f [2] d1 64 [2] ca 2a [2] f7 }

  condition:
    any of them
}