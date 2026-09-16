rule TTP_XOR_MULT_DOSStub_f367 {
  strings:
    $key_f367 = { a7 0f [2] d3 17 [2] 94 15 [2] d3 04 [2] 9d 08 [2] 91 02 [2] 86 09 [2] 9d 47 [2] a0 }

  condition:
    any of them
}