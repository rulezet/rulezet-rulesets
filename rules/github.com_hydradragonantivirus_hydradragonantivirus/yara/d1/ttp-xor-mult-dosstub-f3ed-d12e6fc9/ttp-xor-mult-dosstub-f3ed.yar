rule TTP_XOR_MULT_DOSStub_f3ed {
  strings:
    $key_f3ed = { a7 85 [2] d3 9d [2] 94 9f [2] d3 8e [2] 9d 82 [2] 91 88 [2] 86 83 [2] 9d cd [2] a0 }

  condition:
    any of them
}