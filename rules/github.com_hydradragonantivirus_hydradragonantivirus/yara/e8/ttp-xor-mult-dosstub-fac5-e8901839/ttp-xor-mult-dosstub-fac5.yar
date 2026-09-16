rule TTP_XOR_MULT_DOSStub_fac5 {
  strings:
    $key_fac5 = { ae ad [2] da b5 [2] 9d b7 [2] da a6 [2] 94 aa [2] 98 a0 [2] 8f ab [2] 94 e5 [2] a9 }

  condition:
    any of them
}