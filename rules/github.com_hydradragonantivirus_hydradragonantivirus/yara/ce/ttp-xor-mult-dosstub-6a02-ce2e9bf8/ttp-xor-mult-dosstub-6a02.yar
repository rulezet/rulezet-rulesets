rule TTP_XOR_MULT_DOSStub_6a02 {
  strings:
    $key_6a02 = { 3e 6a [2] 4a 72 [2] 0d 70 [2] 4a 61 [2] 04 6d [2] 08 67 [2] 1f 6c [2] 04 22 [2] 39 }

  condition:
    any of them
}