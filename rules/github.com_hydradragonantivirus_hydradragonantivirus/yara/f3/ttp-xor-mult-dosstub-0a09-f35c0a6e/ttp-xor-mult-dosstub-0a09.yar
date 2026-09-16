rule TTP_XOR_MULT_DOSStub_0a09 {
  strings:
    $key_0a09 = { 5e 61 [2] 2a 79 [2] 6d 7b [2] 2a 6a [2] 64 66 [2] 68 6c [2] 7f 67 [2] 64 29 [2] 59 }

  condition:
    any of them
}