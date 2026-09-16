rule TTP_XOR_MULT_DOSStub_1cef {
  strings:
    $key_1cef = { 48 87 [2] 3c 9f [2] 7b 9d [2] 3c 8c [2] 72 80 [2] 7e 8a [2] 69 81 [2] 72 cf [2] 4f }

  condition:
    any of them
}