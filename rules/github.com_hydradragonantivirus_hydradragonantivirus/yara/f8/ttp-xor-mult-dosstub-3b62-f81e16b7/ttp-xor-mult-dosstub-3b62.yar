rule TTP_XOR_MULT_DOSStub_3b62 {
  strings:
    $key_3b62 = { 6f 0a [2] 1b 12 [2] 5c 10 [2] 1b 01 [2] 55 0d [2] 59 07 [2] 4e 0c [2] 55 42 [2] 68 }

  condition:
    any of them
}