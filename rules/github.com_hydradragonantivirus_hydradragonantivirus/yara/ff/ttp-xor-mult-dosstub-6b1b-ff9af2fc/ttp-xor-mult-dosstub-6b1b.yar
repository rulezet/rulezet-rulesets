rule TTP_XOR_MULT_DOSStub_6b1b {
  strings:
    $key_6b1b = { 3f 73 [2] 4b 6b [2] 0c 69 [2] 4b 78 [2] 05 74 [2] 09 7e [2] 1e 75 [2] 05 3b [2] 38 }

  condition:
    any of them
}