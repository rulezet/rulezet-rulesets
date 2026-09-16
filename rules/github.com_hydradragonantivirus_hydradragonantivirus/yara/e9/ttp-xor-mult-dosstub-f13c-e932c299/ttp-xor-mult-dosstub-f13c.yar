rule TTP_XOR_MULT_DOSStub_f13c {
  strings:
    $key_f13c = { a5 54 [2] d1 4c [2] 96 4e [2] d1 5f [2] 9f 53 [2] 93 59 [2] 84 52 [2] 9f 1c [2] a2 }

  condition:
    any of them
}