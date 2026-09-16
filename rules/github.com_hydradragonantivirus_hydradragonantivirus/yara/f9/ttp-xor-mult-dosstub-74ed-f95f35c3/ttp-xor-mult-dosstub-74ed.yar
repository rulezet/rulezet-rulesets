rule TTP_XOR_MULT_DOSStub_74ed {
  strings:
    $key_74ed = { 20 85 [2] 54 9d [2] 13 9f [2] 54 8e [2] 1a 82 [2] 16 88 [2] 01 83 [2] 1a cd [2] 27 }

  condition:
    any of them
}