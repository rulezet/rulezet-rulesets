rule TTP_XOR_MULT_DOSStub_e44c {
  strings:
    $key_e44c = { b0 24 [2] c4 3c [2] 83 3e [2] c4 2f [2] 8a 23 [2] 86 29 [2] 91 22 [2] 8a 6c [2] b7 }

  condition:
    any of them
}