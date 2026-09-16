rule TTP_XOR_MULT_DOSStub_7253 {
  strings:
    $key_7253 = { 26 3b [2] 52 23 [2] 15 21 [2] 52 30 [2] 1c 3c [2] 10 36 [2] 07 3d [2] 1c 73 [2] 21 }

  condition:
    any of them
}