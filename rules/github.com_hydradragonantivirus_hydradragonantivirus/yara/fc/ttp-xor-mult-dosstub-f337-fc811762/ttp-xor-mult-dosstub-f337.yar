rule TTP_XOR_MULT_DOSStub_f337 {
  strings:
    $key_f337 = { a7 5f [2] d3 47 [2] 94 45 [2] d3 54 [2] 9d 58 [2] 91 52 [2] 86 59 [2] 9d 17 [2] a0 }

  condition:
    any of them
}