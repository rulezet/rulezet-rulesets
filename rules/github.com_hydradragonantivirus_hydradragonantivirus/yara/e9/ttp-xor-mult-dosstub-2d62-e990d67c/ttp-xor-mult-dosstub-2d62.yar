rule TTP_XOR_MULT_DOSStub_2d62 {
  strings:
    $key_2d62 = { 79 0a [2] 0d 12 [2] 4a 10 [2] 0d 01 [2] 43 0d [2] 4f 07 [2] 58 0c [2] 43 42 [2] 7e }

  condition:
    any of them
}