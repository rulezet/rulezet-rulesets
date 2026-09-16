rule TTP_XOR_MULT_DOSStub_a9c5 {
  strings:
    $key_a9c5 = { fd ad [2] 89 b5 [2] ce b7 [2] 89 a6 [2] c7 aa [2] cb a0 [2] dc ab [2] c7 e5 [2] fa }

  condition:
    any of them
}