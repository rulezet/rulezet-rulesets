rule TTP_XOR_MULT_DOSStub_0212 {
  strings:
    $key_0212 = { 56 7a [2] 22 62 [2] 65 60 [2] 22 71 [2] 6c 7d [2] 60 77 [2] 77 7c [2] 6c 32 [2] 51 }

  condition:
    any of them
}