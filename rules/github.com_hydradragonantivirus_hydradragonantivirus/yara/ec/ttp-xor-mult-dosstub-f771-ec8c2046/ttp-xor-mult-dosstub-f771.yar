rule TTP_XOR_MULT_DOSStub_f771 {
  strings:
    $key_f771 = { a3 19 [2] d7 01 [2] 90 03 [2] d7 12 [2] 99 1e [2] 95 14 [2] 82 1f [2] 99 51 [2] a4 }

  condition:
    any of them
}