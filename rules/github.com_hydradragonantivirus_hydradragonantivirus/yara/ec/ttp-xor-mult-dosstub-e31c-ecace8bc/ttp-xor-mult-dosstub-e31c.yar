rule TTP_XOR_MULT_DOSStub_e31c {
  strings:
    $key_e31c = { b7 74 [2] c3 6c [2] 84 6e [2] c3 7f [2] 8d 73 [2] 81 79 [2] 96 72 [2] 8d 3c [2] b0 }

  condition:
    any of them
}