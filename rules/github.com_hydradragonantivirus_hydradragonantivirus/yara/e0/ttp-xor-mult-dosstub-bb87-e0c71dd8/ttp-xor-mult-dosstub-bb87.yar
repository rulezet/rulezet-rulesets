rule TTP_XOR_MULT_DOSStub_bb87 {
  strings:
    $key_bb87 = { ef ef [2] 9b f7 [2] dc f5 [2] 9b e4 [2] d5 e8 [2] d9 e2 [2] ce e9 [2] d5 a7 [2] e8 }

  condition:
    any of them
}