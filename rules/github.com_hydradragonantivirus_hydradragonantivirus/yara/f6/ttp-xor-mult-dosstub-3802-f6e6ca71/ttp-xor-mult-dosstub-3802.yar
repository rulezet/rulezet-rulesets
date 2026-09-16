rule TTP_XOR_MULT_DOSStub_3802 {
  strings:
    $key_3802 = { 6c 6a [2] 18 72 [2] 5f 70 [2] 18 61 [2] 56 6d [2] 5a 67 [2] 4d 6c [2] 56 22 [2] 6b }

  condition:
    any of them
}