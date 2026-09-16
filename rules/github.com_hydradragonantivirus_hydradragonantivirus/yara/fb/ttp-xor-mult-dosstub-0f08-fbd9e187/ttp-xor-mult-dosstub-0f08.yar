rule TTP_XOR_MULT_DOSStub_0f08 {
  strings:
    $key_0f08 = { 5b 60 [2] 2f 78 [2] 68 7a [2] 2f 6b [2] 61 67 [2] 6d 6d [2] 7a 66 [2] 61 28 [2] 5c }

  condition:
    any of them
}