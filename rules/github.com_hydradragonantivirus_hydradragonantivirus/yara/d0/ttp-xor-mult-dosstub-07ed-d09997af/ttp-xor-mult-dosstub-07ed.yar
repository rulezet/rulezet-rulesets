rule TTP_XOR_MULT_DOSStub_07ed {
  strings:
    $key_07ed = { 53 85 [2] 27 9d [2] 60 9f [2] 27 8e [2] 69 82 [2] 65 88 [2] 72 83 [2] 69 cd [2] 54 }

  condition:
    any of them
}