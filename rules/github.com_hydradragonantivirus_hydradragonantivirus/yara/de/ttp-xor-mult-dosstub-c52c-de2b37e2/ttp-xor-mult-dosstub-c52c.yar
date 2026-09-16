rule TTP_XOR_MULT_DOSStub_c52c {
  strings:
    $key_c52c = { 91 44 [2] e5 5c [2] a2 5e [2] e5 4f [2] ab 43 [2] a7 49 [2] b0 42 [2] ab 0c [2] 96 }

  condition:
    any of them
}