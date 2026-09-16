rule TTP_XOR_MULT_DOSStub_fad4 {
  strings:
    $key_fad4 = { ae bc [2] da a4 [2] 9d a6 [2] da b7 [2] 94 bb [2] 98 b1 [2] 8f ba [2] 94 f4 [2] a9 }

  condition:
    any of them
}