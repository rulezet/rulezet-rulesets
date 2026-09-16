rule TTP_XOR_MULT_DOSStub_e26b {
  strings:
    $key_e26b = { b6 03 [2] c2 1b [2] 85 19 [2] c2 08 [2] 8c 04 [2] 80 0e [2] 97 05 [2] 8c 4b [2] b1 }

  condition:
    any of them
}