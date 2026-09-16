rule TTP_XOR_MULT_DOSStub_66ed {
  strings:
    $key_66ed = { 32 85 [2] 46 9d [2] 01 9f [2] 46 8e [2] 08 82 [2] 04 88 [2] 13 83 [2] 08 cd [2] 35 }

  condition:
    any of them
}