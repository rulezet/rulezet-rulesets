rule TTP_XOR_MULT_DOSStub_e073 {
  strings:
    $key_e073 = { b4 1b [2] c0 03 [2] 87 01 [2] c0 10 [2] 8e 1c [2] 82 16 [2] 95 1d [2] 8e 53 [2] b3 }

  condition:
    any of them
}