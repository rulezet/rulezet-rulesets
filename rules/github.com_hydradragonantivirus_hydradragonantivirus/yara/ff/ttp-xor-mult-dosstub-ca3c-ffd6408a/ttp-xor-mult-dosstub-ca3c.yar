rule TTP_XOR_MULT_DOSStub_ca3c {
  strings:
    $key_ca3c = { 9e 54 [2] ea 4c [2] ad 4e [2] ea 5f [2] a4 53 [2] a8 59 [2] bf 52 [2] a4 1c [2] 99 }

  condition:
    any of them
}