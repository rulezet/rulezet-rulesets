rule TTP_XOR_MULT_DOSStub_0053 {
  strings:
    $key_0053 = { 54 3b [2] 20 23 [2] 67 21 [2] 20 30 [2] 6e 3c [2] 62 36 [2] 75 3d [2] 6e 73 [2] 53 }

  condition:
    any of them
}