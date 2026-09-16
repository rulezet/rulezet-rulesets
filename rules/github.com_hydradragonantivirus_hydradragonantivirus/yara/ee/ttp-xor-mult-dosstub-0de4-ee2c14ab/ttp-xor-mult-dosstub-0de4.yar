rule TTP_XOR_MULT_DOSStub_0de4 {
  strings:
    $key_0de4 = { 59 8c [2] 2d 94 [2] 6a 96 [2] 2d 87 [2] 63 8b [2] 6f 81 [2] 78 8a [2] 63 c4 [2] 5e }

  condition:
    any of them
}