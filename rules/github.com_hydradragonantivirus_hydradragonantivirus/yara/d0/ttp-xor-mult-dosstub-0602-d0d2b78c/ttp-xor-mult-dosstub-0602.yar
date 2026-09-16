rule TTP_XOR_MULT_DOSStub_0602 {
  strings:
    $key_0602 = { 52 6a [2] 26 72 [2] 61 70 [2] 26 61 [2] 68 6d [2] 64 67 [2] 73 6c [2] 68 22 [2] 55 }

  condition:
    any of them
}