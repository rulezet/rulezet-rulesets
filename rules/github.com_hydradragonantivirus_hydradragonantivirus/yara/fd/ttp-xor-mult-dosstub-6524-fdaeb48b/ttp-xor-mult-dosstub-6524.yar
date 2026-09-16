rule TTP_XOR_MULT_DOSStub_6524 {
  strings:
    $key_6524 = { 31 4c [2] 45 54 [2] 02 56 [2] 45 47 [2] 0b 4b [2] 07 41 [2] 10 4a [2] 0b 04 [2] 36 }

  condition:
    any of them
}