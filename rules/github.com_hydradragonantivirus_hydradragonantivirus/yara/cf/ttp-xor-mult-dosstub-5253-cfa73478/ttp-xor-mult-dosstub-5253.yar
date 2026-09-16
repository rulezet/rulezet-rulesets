rule TTP_XOR_MULT_DOSStub_5253 {
  strings:
    $key_5253 = { 06 3b [2] 72 23 [2] 35 21 [2] 72 30 [2] 3c 3c [2] 30 36 [2] 27 3d [2] 3c 73 [2] 01 }

  condition:
    any of them
}