rule TTP_XOR_MULT_DOSStub_f3fd {
  strings:
    $key_f3fd = { a7 95 [2] d3 8d [2] 94 8f [2] d3 9e [2] 9d 92 [2] 91 98 [2] 86 93 [2] 9d dd [2] a0 }

  condition:
    any of them
}