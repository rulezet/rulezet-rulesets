rule TTP_XOR_MULT_DOSStub_f23c {
  strings:
    $key_f23c = { a6 54 [2] d2 4c [2] 95 4e [2] d2 5f [2] 9c 53 [2] 90 59 [2] 87 52 [2] 9c 1c [2] a1 }

  condition:
    any of them
}