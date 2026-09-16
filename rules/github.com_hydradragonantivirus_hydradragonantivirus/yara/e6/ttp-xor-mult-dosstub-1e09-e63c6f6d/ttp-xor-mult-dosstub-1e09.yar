rule TTP_XOR_MULT_DOSStub_1e09 {
  strings:
    $key_1e09 = { 4a 61 [2] 3e 79 [2] 79 7b [2] 3e 6a [2] 70 66 [2] 7c 6c [2] 6b 67 [2] 70 29 [2] 4d }

  condition:
    any of them
}