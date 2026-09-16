rule TTP_XOR_MULT_DOSStub_f16b {
  strings:
    $key_f16b = { a5 03 [2] d1 1b [2] 96 19 [2] d1 08 [2] 9f 04 [2] 93 0e [2] 84 05 [2] 9f 4b [2] a2 }

  condition:
    any of them
}