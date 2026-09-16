rule TTP_XOR_MULT_DOSStub_67ed {
  strings:
    $key_67ed = { 33 85 [2] 47 9d [2] 00 9f [2] 47 8e [2] 09 82 [2] 05 88 [2] 12 83 [2] 09 cd [2] 34 }

  condition:
    any of them
}