rule TTP_XOR_MULT_DOSStub_7cef {
  strings:
    $key_7cef = { 28 87 [2] 5c 9f [2] 1b 9d [2] 5c 8c [2] 12 80 [2] 1e 8a [2] 09 81 [2] 12 cf [2] 2f }

  condition:
    any of them
}