rule TTP_XOR_MULT_DOSStub_f7ef {
  strings:
    $key_f7ef = { a3 87 [2] d7 9f [2] 90 9d [2] d7 8c [2] 99 80 [2] 95 8a [2] 82 81 [2] 99 cf [2] a4 }

  condition:
    any of them
}