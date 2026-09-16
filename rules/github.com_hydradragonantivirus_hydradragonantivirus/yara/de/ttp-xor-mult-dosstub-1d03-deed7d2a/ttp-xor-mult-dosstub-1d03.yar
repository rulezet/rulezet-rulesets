rule TTP_XOR_MULT_DOSStub_1d03 {
  strings:
    $key_1d03 = { 49 6b [2] 3d 73 [2] 7a 71 [2] 3d 60 [2] 73 6c [2] 7f 66 [2] 68 6d [2] 73 23 [2] 4e }

  condition:
    any of them
}