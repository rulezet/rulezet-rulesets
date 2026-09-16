rule TTP_XOR_MULT_DOSStub_c37c {
  strings:
    $key_c37c = { 97 14 [2] e3 0c [2] a4 0e [2] e3 1f [2] ad 13 [2] a1 19 [2] b6 12 [2] ad 5c [2] 90 }

  condition:
    any of them
}