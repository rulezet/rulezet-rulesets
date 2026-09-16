rule TTP_XOR_MULT_DOSStub_2cef {
  strings:
    $key_2cef = { 78 87 [2] 0c 9f [2] 4b 9d [2] 0c 8c [2] 42 80 [2] 4e 8a [2] 59 81 [2] 42 cf [2] 7f }

  condition:
    any of them
}