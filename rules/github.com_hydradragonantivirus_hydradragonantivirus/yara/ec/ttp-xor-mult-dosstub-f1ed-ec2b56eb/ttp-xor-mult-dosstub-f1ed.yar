rule TTP_XOR_MULT_DOSStub_f1ed {
  strings:
    $key_f1ed = { a5 85 [2] d1 9d [2] 96 9f [2] d1 8e [2] 9f 82 [2] 93 88 [2] 84 83 [2] 9f cd [2] a2 }

  condition:
    any of them
}