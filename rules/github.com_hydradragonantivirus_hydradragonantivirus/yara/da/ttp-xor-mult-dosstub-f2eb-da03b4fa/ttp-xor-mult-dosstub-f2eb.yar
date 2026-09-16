rule TTP_XOR_MULT_DOSStub_f2eb {
  strings:
    $key_f2eb = { a6 83 [2] d2 9b [2] 95 99 [2] d2 88 [2] 9c 84 [2] 90 8e [2] 87 85 [2] 9c cb [2] a1 }

  condition:
    any of them
}