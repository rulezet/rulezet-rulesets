rule TTP_XOR_MULT_DOSStub_e74c {
  strings:
    $key_e74c = { b3 24 [2] c7 3c [2] 80 3e [2] c7 2f [2] 89 23 [2] 85 29 [2] 92 22 [2] 89 6c [2] b4 }

  condition:
    any of them
}