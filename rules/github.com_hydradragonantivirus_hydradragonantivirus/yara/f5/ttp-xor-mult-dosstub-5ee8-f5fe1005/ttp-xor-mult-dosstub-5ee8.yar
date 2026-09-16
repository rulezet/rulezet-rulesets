rule TTP_XOR_MULT_DOSStub_5ee8 {
  strings:
    $key_5ee8 = { 0a 80 [2] 7e 98 [2] 39 9a [2] 7e 8b [2] 30 87 [2] 3c 8d [2] 2b 86 [2] 30 c8 [2] 0d }

  condition:
    any of them
}