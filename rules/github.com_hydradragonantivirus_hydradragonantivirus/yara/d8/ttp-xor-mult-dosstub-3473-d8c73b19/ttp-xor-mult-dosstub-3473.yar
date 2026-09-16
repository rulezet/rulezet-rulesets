rule TTP_XOR_MULT_DOSStub_3473 {
  strings:
    $key_3473 = { 60 1b [2] 14 03 [2] 53 01 [2] 14 10 [2] 5a 1c [2] 56 16 [2] 41 1d [2] 5a 53 [2] 67 }

  condition:
    any of them
}