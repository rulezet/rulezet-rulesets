rule TTP_XOR_MULT_DOSStub_f35e {
  strings:
    $key_f35e = { a7 36 [2] d3 2e [2] 94 2c [2] d3 3d [2] 9d 31 [2] 91 3b [2] 86 30 [2] 9d 7e [2] a0 }

  condition:
    any of them
}