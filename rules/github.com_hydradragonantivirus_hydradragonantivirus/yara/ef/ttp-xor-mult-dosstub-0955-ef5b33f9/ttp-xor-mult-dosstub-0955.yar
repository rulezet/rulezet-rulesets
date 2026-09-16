rule TTP_XOR_MULT_DOSStub_0955 {
  strings:
    $key_0955 = { 5d 3d [2] 29 25 [2] 6e 27 [2] 29 36 [2] 67 3a [2] 6b 30 [2] 7c 3b [2] 67 75 [2] 5a }

  condition:
    any of them
}