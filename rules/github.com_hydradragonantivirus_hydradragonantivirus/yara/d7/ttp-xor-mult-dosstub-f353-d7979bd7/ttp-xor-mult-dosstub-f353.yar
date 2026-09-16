rule TTP_XOR_MULT_DOSStub_f353 {
  strings:
    $key_f353 = { a7 3b [2] d3 23 [2] 94 21 [2] d3 30 [2] 9d 3c [2] 91 36 [2] 86 3d [2] 9d 73 [2] a0 }

  condition:
    any of them
}