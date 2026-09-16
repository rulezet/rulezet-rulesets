rule TTP_XOR_MULT_DOSStub_5073 {
  strings:
    $key_5073 = { 04 1b [2] 70 03 [2] 37 01 [2] 70 10 [2] 3e 1c [2] 32 16 [2] 25 1d [2] 3e 53 [2] 03 }

  condition:
    any of them
}