rule TTP_XOR_MULT_DOSStub_21ed {
  strings:
    $key_21ed = { 75 85 [2] 01 9d [2] 46 9f [2] 01 8e [2] 4f 82 [2] 43 88 [2] 54 83 [2] 4f cd [2] 72 }

  condition:
    any of them
}