rule TTP_XOR_MULT_DOSStub_1e02 {
  strings:
    $key_1e02 = { 4a 6a [2] 3e 72 [2] 79 70 [2] 3e 61 [2] 70 6d [2] 7c 67 [2] 6b 6c [2] 70 22 [2] 4d }

  condition:
    any of them
}