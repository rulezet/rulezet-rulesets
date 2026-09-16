rule TTP_XOR_MULT_DOSStub_ecef {
  strings:
    $key_ecef = { b8 87 [2] cc 9f [2] 8b 9d [2] cc 8c [2] 82 80 [2] 8e 8a [2] 99 81 [2] 82 cf [2] bf }

  condition:
    any of them
}