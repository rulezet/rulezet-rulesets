rule TTP_XOR_MULT_DOSStub_bbc2 {
  strings:
    $key_bbc2 = { ef aa [2] 9b b2 [2] dc b0 [2] 9b a1 [2] d5 ad [2] d9 a7 [2] ce ac [2] d5 e2 [2] e8 }

  condition:
    any of them
}