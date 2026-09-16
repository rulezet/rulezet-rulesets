rule TTP_XOR_MULT_DOSStub_bb8b {
  strings:
    $key_bb8b = { ef e3 [2] 9b fb [2] dc f9 [2] 9b e8 [2] d5 e4 [2] d9 ee [2] ce e5 [2] d5 ab [2] e8 }

  condition:
    any of them
}