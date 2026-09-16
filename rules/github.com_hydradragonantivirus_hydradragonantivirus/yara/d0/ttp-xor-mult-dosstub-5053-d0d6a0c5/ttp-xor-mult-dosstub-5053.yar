rule TTP_XOR_MULT_DOSStub_5053 {
  strings:
    $key_5053 = { 04 3b [2] 70 23 [2] 37 21 [2] 70 30 [2] 3e 3c [2] 32 36 [2] 25 3d [2] 3e 73 [2] 03 }

  condition:
    any of them
}