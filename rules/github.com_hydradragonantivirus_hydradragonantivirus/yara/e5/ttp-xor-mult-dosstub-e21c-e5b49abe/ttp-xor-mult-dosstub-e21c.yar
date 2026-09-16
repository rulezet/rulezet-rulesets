rule TTP_XOR_MULT_DOSStub_e21c {
  strings:
    $key_e21c = { b6 74 [2] c2 6c [2] 85 6e [2] c2 7f [2] 8c 73 [2] 80 79 [2] 97 72 [2] 8c 3c [2] b1 }

  condition:
    any of them
}