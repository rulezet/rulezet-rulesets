rule TTP_XOR_MULT_DOSStub_65f5 {
  strings:
    $key_65f5 = { 31 9d [2] 45 85 [2] 02 87 [2] 45 96 [2] 0b 9a [2] 07 90 [2] 10 9b [2] 0b d5 [2] 36 }

  condition:
    any of them
}