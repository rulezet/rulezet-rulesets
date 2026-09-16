rule TTP_XOR_MULT_DOSStub_a9d8 {
  strings:
    $key_a9d8 = { fd b0 [2] 89 a8 [2] ce aa [2] 89 bb [2] c7 b7 [2] cb bd [2] dc b6 [2] c7 f8 [2] fa }

  condition:
    any of them
}