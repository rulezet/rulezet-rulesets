rule TTP_XOR_MULT_DOSStub_0d12 {
  strings:
    $key_0d12 = { 59 7a [2] 2d 62 [2] 6a 60 [2] 2d 71 [2] 63 7d [2] 6f 77 [2] 78 7c [2] 63 32 [2] 5e }

  condition:
    any of them
}