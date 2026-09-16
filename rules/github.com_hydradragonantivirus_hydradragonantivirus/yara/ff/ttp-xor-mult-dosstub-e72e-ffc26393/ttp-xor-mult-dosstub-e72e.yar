rule TTP_XOR_MULT_DOSStub_e72e {
  strings:
    $key_e72e = { b3 46 [2] c7 5e [2] 80 5c [2] c7 4d [2] 89 41 [2] 85 4b [2] 92 40 [2] 89 0e [2] b4 }

  condition:
    any of them
}