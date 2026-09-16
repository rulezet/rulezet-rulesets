rule TTP_XOR_MULT_DOSStub_282d {
  strings:
    $key_282d = { 7c 45 [2] 08 5d [2] 4f 5f [2] 08 4e [2] 46 42 [2] 4a 48 [2] 5d 43 [2] 46 0d [2] 7b }

  condition:
    any of them
}