rule TTP_XOR_MULT_DOSStub_6562 {
  strings:
    $key_6562 = { 31 0a [2] 45 12 [2] 02 10 [2] 45 01 [2] 0b 0d [2] 07 07 [2] 10 0c [2] 0b 42 [2] 36 }

  condition:
    any of them
}