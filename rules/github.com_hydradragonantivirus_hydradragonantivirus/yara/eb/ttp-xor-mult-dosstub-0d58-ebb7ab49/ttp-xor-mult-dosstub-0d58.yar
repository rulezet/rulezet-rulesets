rule TTP_XOR_MULT_DOSStub_0d58 {
  strings:
    $key_0d58 = { 59 30 [2] 2d 28 [2] 6a 2a [2] 2d 3b [2] 63 37 [2] 6f 3d [2] 78 36 [2] 63 78 [2] 5e }

  condition:
    any of them
}