rule TTP_XOR_MULT_DOSStub_7ce8 {
  strings:
    $key_7ce8 = { 28 80 [2] 5c 98 [2] 1b 9a [2] 5c 8b [2] 12 87 [2] 1e 8d [2] 09 86 [2] 12 c8 [2] 2f }

  condition:
    any of them
}