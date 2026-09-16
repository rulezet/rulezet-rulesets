rule TTP_XOR_MULT_DOSStub_6535 {
  strings:
    $key_6535 = { 31 5d [2] 45 45 [2] 02 47 [2] 45 56 [2] 0b 5a [2] 07 50 [2] 10 5b [2] 0b 15 [2] 36 }

  condition:
    any of them
}