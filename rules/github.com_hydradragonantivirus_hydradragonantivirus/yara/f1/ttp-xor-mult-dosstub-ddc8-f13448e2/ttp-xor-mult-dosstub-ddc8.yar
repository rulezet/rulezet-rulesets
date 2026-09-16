rule TTP_XOR_MULT_DOSStub_ddc8 {
  strings:
    $key_ddc8 = { 89 a0 [2] fd b8 [2] ba ba [2] fd ab [2] b3 a7 [2] bf ad [2] a8 a6 [2] b3 e8 [2] 8e }

  condition:
    any of them
}