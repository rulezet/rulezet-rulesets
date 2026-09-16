rule TTP_XOR_MULT_DOSStub_56ed {
  strings:
    $key_56ed = { 02 85 [2] 76 9d [2] 31 9f [2] 76 8e [2] 38 82 [2] 34 88 [2] 23 83 [2] 38 cd [2] 05 }

  condition:
    any of them
}