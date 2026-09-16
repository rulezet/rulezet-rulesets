rule TTP_XOR_MULT_DOSStub_1953 {
  strings:
    $key_1953 = { 4d 3b [2] 39 23 [2] 7e 21 [2] 39 30 [2] 77 3c [2] 7b 36 [2] 6c 3d [2] 77 73 [2] 4a }

  condition:
    any of them
}