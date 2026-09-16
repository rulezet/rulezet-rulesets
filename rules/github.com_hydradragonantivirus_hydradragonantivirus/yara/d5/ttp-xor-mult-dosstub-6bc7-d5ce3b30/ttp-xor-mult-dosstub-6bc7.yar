rule TTP_XOR_MULT_DOSStub_6bc7 {
  strings:
    $key_6bc7 = { 3f af [2] 4b b7 [2] 0c b5 [2] 4b a4 [2] 05 a8 [2] 09 a2 [2] 1e a9 [2] 05 e7 [2] 38 }

  condition:
    any of them
}