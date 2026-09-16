rule TTP_XOR_MULT_DOSStub_c33c {
  strings:
    $key_c33c = { 97 54 [2] e3 4c [2] a4 4e [2] e3 5f [2] ad 53 [2] a1 59 [2] b6 52 [2] ad 1c [2] 90 }

  condition:
    any of them
}