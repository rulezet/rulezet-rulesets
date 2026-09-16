rule TTP_XOR_MULT_DOSStub_53ed {
  strings:
    $key_53ed = { 07 85 [2] 73 9d [2] 34 9f [2] 73 8e [2] 3d 82 [2] 31 88 [2] 26 83 [2] 3d cd [2] 00 }

  condition:
    any of them
}