rule TTP_XOR_MULT_DOSStub_4ce8 {
  strings:
    $key_4ce8 = { 18 80 [2] 6c 98 [2] 2b 9a [2] 6c 8b [2] 22 87 [2] 2e 8d [2] 39 86 [2] 22 c8 [2] 1f }

  condition:
    any of them
}