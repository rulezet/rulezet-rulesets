rule TTP_XOR_MULT_DOSStub_0d73 {
  strings:
    $key_0d73 = { 59 1b [2] 2d 03 [2] 6a 01 [2] 2d 10 [2] 63 1c [2] 6f 16 [2] 78 1d [2] 63 53 [2] 5e }

  condition:
    any of them
}