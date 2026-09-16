rule TTP_XOR_MULT_DOSStub_e23e {
  strings:
    $key_e23e = { b6 56 [2] c2 4e [2] 85 4c [2] c2 5d [2] 8c 51 [2] 80 5b [2] 97 50 [2] 8c 1e [2] b1 }

  condition:
    any of them
}