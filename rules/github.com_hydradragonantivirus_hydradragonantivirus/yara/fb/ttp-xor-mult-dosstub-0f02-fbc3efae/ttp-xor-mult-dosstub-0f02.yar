rule TTP_XOR_MULT_DOSStub_0f02 {
  strings:
    $key_0f02 = { 5b 6a [2] 2f 72 [2] 68 70 [2] 2f 61 [2] 61 6d [2] 6d 67 [2] 7a 6c [2] 61 22 [2] 5c }

  condition:
    any of them
}