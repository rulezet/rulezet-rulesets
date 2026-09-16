rule TTP_XOR_MULT_DOSStub_3955 {
  strings:
    $key_3955 = { 6d 3d [2] 19 25 [2] 5e 27 [2] 19 36 [2] 57 3a [2] 5b 30 [2] 4c 3b [2] 57 75 [2] 6a }

  condition:
    any of them
}