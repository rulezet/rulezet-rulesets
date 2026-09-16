rule TTP_XOR_MULT_DOSStub_1d62 {
  strings:
    $key_1d62 = { 49 0a [2] 3d 12 [2] 7a 10 [2] 3d 01 [2] 73 0d [2] 7f 07 [2] 68 0c [2] 73 42 [2] 4e }

  condition:
    any of them
}