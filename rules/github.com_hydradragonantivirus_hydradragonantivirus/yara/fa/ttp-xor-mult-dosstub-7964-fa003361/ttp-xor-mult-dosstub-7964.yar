rule TTP_XOR_MULT_DOSStub_7964 {
  strings:
    $key_7964 = { 2d 0c [2] 59 14 [2] 1e 16 [2] 59 07 [2] 17 0b [2] 1b 01 [2] 0c 0a [2] 17 44 [2] 2a }

  condition:
    any of them
}