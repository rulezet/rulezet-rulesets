rule TTP_XOR_MULT_DOSStub_c5ed {
  strings:
    $key_c5ed = { 91 85 [2] e5 9d [2] a2 9f [2] e5 8e [2] ab 82 [2] a7 88 [2] b0 83 [2] ab cd [2] 96 }

  condition:
    any of them
}