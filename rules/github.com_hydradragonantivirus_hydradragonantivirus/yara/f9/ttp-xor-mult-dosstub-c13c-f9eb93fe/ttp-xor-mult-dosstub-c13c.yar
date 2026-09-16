rule TTP_XOR_MULT_DOSStub_c13c {
  strings:
    $key_c13c = { 95 54 [2] e1 4c [2] a6 4e [2] e1 5f [2] af 53 [2] a3 59 [2] b4 52 [2] af 1c [2] 92 }

  condition:
    any of them
}