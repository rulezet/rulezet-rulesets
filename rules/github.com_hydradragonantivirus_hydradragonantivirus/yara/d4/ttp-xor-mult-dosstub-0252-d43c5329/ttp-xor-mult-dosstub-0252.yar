rule TTP_XOR_MULT_DOSStub_0252 {
  strings:
    $key_0252 = { 56 3a [2] 22 22 [2] 65 20 [2] 22 31 [2] 6c 3d [2] 60 37 [2] 77 3c [2] 6c 72 [2] 51 }

  condition:
    any of them
}