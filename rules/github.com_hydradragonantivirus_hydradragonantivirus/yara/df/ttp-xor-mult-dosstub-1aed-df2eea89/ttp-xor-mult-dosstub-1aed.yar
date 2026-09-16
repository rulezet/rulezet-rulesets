rule TTP_XOR_MULT_DOSStub_1aed {
  strings:
    $key_1aed = { 4e 85 [2] 3a 9d [2] 7d 9f [2] 3a 8e [2] 74 82 [2] 78 88 [2] 6f 83 [2] 74 cd [2] 49 }

  condition:
    any of them
}