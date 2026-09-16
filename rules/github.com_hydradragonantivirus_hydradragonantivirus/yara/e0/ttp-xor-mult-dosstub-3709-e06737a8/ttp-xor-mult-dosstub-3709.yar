rule TTP_XOR_MULT_DOSStub_3709 {
  strings:
    $key_3709 = { 63 61 [2] 17 79 [2] 50 7b [2] 17 6a [2] 59 66 [2] 55 6c [2] 42 67 [2] 59 29 [2] 64 }

  condition:
    any of them
}