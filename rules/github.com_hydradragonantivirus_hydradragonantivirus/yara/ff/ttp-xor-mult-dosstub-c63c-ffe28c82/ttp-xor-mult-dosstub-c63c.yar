rule TTP_XOR_MULT_DOSStub_c63c {
  strings:
    $key_c63c = { 92 54 [2] e6 4c [2] a1 4e [2] e6 5f [2] a8 53 [2] a4 59 [2] b3 52 [2] a8 1c [2] 95 }

  condition:
    any of them
}