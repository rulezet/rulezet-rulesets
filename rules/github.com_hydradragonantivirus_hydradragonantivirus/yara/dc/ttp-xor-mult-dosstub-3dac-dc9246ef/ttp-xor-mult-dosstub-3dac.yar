rule TTP_XOR_MULT_DOSStub_3dac {
  strings:
    $key_3dac = { 69 c4 [2] 1d dc [2] 5a de [2] 1d cf [2] 53 c3 [2] 5f c9 [2] 48 c2 [2] 53 8c [2] 6e }

  condition:
    any of them
}