rule TTP_XOR_MULT_DOSStub_13ed {
  strings:
    $key_13ed = { 47 85 [2] 33 9d [2] 74 9f [2] 33 8e [2] 7d 82 [2] 71 88 [2] 66 83 [2] 7d cd [2] 40 }

  condition:
    any of them
}