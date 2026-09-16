rule TTP_XOR_MULT_DOSStub_3402 {
  strings:
    $key_3402 = { 60 6a [2] 14 72 [2] 53 70 [2] 14 61 [2] 5a 6d [2] 56 67 [2] 41 6c [2] 5a 22 [2] 67 }

  condition:
    any of them
}