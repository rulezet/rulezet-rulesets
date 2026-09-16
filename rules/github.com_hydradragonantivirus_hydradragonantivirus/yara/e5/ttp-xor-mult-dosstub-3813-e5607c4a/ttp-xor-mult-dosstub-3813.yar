rule TTP_XOR_MULT_DOSStub_3813 {
  strings:
    $key_3813 = { 6c 7b [2] 18 63 [2] 5f 61 [2] 18 70 [2] 56 7c [2] 5a 76 [2] 4d 7d [2] 56 33 [2] 6b }

  condition:
    any of them
}