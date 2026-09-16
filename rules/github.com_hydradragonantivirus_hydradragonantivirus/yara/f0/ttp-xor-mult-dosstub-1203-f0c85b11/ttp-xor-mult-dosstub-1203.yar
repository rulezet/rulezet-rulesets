rule TTP_XOR_MULT_DOSStub_1203 {
  strings:
    $key_1203 = { 46 6b [2] 32 73 [2] 75 71 [2] 32 60 [2] 7c 6c [2] 70 66 [2] 67 6d [2] 7c 23 [2] 41 }

  condition:
    any of them
}