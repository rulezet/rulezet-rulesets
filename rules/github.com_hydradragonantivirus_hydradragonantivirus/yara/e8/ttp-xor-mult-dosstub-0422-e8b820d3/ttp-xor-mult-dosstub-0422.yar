rule TTP_XOR_MULT_DOSStub_0422 {
  strings:
    $key_0422 = { 50 4a [2] 24 52 [2] 63 50 [2] 24 41 [2] 6a 4d [2] 66 47 [2] 71 4c [2] 6a 02 [2] 57 }

  condition:
    any of them
}