rule TTP_XOR_MULT_DOSStub_f610 {
  strings:
    $key_f610 = { a2 78 [2] d6 60 [2] 91 62 [2] d6 73 [2] 98 7f [2] 94 75 [2] 83 7e [2] 98 30 [2] a5 }

  condition:
    any of them
}