rule TTP_XOR_MULT_DOSStub_0d62 {
  strings:
    $key_0d62 = { 59 0a [2] 2d 12 [2] 6a 10 [2] 2d 01 [2] 63 0d [2] 6f 07 [2] 78 0c [2] 63 42 [2] 5e }

  condition:
    any of them
}