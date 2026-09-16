rule TTP_XOR_MULT_DOSStub_c4ed {
  strings:
    $key_c4ed = { 90 85 [2] e4 9d [2] a3 9f [2] e4 8e [2] aa 82 [2] a6 88 [2] b1 83 [2] aa cd [2] 97 }

  condition:
    any of them
}