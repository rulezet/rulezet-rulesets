rule TTP_XOR_MULT_DOSStub_3739 {
  strings:
    $key_3739 = { 63 51 [2] 17 49 [2] 50 4b [2] 17 5a [2] 59 56 [2] 55 5c [2] 42 57 [2] 59 19 [2] 64 }

  condition:
    any of them
}