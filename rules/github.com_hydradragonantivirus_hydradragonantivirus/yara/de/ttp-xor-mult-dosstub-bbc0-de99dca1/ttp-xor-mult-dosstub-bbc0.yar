rule TTP_XOR_MULT_DOSStub_bbc0 {
  strings:
    $key_bbc0 = { ef a8 [2] 9b b0 [2] dc b2 [2] 9b a3 [2] d5 af [2] d9 a5 [2] ce ae [2] d5 e0 [2] e8 }

  condition:
    any of them
}