rule TTP_XOR_MULT_DOSStub_0a12 {
  strings:
    $key_0a12 = { 5e 7a [2] 2a 62 [2] 6d 60 [2] 2a 71 [2] 64 7d [2] 68 77 [2] 7f 7c [2] 64 32 [2] 59 }

  condition:
    any of them
}