rule TTP_XOR_MULT_DOSStub_6d53 {
  strings:
    $key_6d53 = { 39 3b [2] 4d 23 [2] 0a 21 [2] 4d 30 [2] 03 3c [2] 0f 36 [2] 18 3d [2] 03 73 [2] 3e }

  condition:
    any of them
}