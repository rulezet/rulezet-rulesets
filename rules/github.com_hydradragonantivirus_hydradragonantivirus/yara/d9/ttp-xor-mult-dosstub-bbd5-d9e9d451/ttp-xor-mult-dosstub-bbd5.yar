rule TTP_XOR_MULT_DOSStub_bbd5 {
  strings:
    $key_bbd5 = { ef bd [2] 9b a5 [2] dc a7 [2] 9b b6 [2] d5 ba [2] d9 b0 [2] ce bb [2] d5 f5 [2] e8 }

  condition:
    any of them
}