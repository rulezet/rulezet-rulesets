rule TTP_XOR_MULT_DOSStub_0203 {
  strings:
    $key_0203 = { 56 6b [2] 22 73 [2] 65 71 [2] 22 60 [2] 6c 6c [2] 60 66 [2] 77 6d [2] 6c 23 [2] 51 }

  condition:
    any of them
}