rule TTP_XOR_MULT_DOSStub_1958 {
  strings:
    $key_1958 = { 4d 30 [2] 39 28 [2] 7e 2a [2] 39 3b [2] 77 37 [2] 7b 3d [2] 6c 36 [2] 77 78 [2] 4a }

  condition:
    any of them
}