rule TTP_XOR_MULT_DOSStub_ac6b {
  strings:
    $key_ac6b = { f8 03 [2] 8c 1b [2] cb 19 [2] 8c 08 [2] c2 04 [2] ce 0e [2] d9 05 [2] c2 4b [2] ff }

  condition:
    any of them
}