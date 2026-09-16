rule TTP_XOR_MULT_DOSStub_0d78 {
  strings:
    $key_0d78 = { 59 10 [2] 2d 08 [2] 6a 0a [2] 2d 1b [2] 63 17 [2] 6f 1d [2] 78 16 [2] 63 58 [2] 5e }

  condition:
    any of them
}