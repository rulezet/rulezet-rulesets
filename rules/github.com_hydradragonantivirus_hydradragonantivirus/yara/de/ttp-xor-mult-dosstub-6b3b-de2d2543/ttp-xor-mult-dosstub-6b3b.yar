rule TTP_XOR_MULT_DOSStub_6b3b {
  strings:
    $key_6b3b = { 3f 53 [2] 4b 4b [2] 0c 49 [2] 4b 58 [2] 05 54 [2] 09 5e [2] 1e 55 [2] 05 1b [2] 38 }

  condition:
    any of them
}