rule TTP_XOR_MULT_DOSStub_e52c {
  strings:
    $key_e52c = { b1 44 [2] c5 5c [2] 82 5e [2] c5 4f [2] 8b 43 [2] 87 49 [2] 90 42 [2] 8b 0c [2] b6 }

  condition:
    any of them
}