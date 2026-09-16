rule TTP_XOR_MULT_DOSStub_e41c {
  strings:
    $key_e41c = { b0 74 [2] c4 6c [2] 83 6e [2] c4 7f [2] 8a 73 [2] 86 79 [2] 91 72 [2] 8a 3c [2] b7 }

  condition:
    any of them
}