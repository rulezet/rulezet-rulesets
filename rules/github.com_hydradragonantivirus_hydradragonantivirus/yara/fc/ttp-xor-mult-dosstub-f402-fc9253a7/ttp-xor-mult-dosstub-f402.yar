rule TTP_XOR_MULT_DOSStub_f402 {
  strings:
    $key_f402 = { a0 6a [2] d4 72 [2] 93 70 [2] d4 61 [2] 9a 6d [2] 96 67 [2] 81 6c [2] 9a 22 [2] a7 }

  condition:
    any of them
}