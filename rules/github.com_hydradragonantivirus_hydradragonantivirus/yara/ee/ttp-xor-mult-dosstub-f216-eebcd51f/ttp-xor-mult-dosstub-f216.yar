rule TTP_XOR_MULT_DOSStub_f216 {
  strings:
    $key_f216 = { a6 7e [2] d2 66 [2] 95 64 [2] d2 75 [2] 9c 79 [2] 90 73 [2] 87 78 [2] 9c 36 [2] a1 }

  condition:
    any of them
}