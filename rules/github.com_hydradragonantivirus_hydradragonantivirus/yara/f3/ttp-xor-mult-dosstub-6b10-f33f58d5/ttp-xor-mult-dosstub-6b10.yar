rule TTP_XOR_MULT_DOSStub_6b10 {
  strings:
    $key_6b10 = { 3f 78 [2] 4b 60 [2] 0c 62 [2] 4b 73 [2] 05 7f [2] 09 75 [2] 1e 7e [2] 05 30 [2] 38 }

  condition:
    any of them
}