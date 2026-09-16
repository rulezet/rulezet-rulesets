rule TTP_XOR_MULT_DOSStub_f33b {
  strings:
    $key_f33b = { a7 53 [2] d3 4b [2] 94 49 [2] d3 58 [2] 9d 54 [2] 91 5e [2] 86 55 [2] 9d 1b [2] a0 }

  condition:
    any of them
}