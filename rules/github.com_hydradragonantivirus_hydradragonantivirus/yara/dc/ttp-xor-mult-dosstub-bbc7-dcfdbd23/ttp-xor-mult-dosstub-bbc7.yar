rule TTP_XOR_MULT_DOSStub_bbc7 {
  strings:
    $key_bbc7 = { ef af [2] 9b b7 [2] dc b5 [2] 9b a4 [2] d5 a8 [2] d9 a2 [2] ce a9 [2] d5 e7 [2] e8 }

  condition:
    any of them
}