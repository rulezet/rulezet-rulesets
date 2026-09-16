rule TTP_XOR_MULT_DOSStub_e7ed {
  strings:
    $key_e7ed = { b3 85 [2] c7 9d [2] 80 9f [2] c7 8e [2] 89 82 [2] 85 88 [2] 92 83 [2] 89 cd [2] b4 }

  condition:
    any of them
}