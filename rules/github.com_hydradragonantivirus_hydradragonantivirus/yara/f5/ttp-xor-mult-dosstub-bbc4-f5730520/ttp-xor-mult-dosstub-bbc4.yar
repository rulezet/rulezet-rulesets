rule TTP_XOR_MULT_DOSStub_bbc4 {
  strings:
    $key_bbc4 = { ef ac [2] 9b b4 [2] dc b6 [2] 9b a7 [2] d5 ab [2] d9 a1 [2] ce aa [2] d5 e4 [2] e8 }

  condition:
    any of them
}