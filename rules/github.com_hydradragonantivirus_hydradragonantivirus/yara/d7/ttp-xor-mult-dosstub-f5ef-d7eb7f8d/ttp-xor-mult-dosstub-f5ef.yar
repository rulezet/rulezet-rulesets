rule TTP_XOR_MULT_DOSStub_f5ef {
  strings:
    $key_f5ef = { a1 87 [2] d5 9f [2] 92 9d [2] d5 8c [2] 9b 80 [2] 97 8a [2] 80 81 [2] 9b cf [2] a6 }

  condition:
    any of them
}