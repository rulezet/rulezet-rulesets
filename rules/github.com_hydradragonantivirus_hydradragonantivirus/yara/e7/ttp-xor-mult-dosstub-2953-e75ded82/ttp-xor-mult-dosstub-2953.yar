rule TTP_XOR_MULT_DOSStub_2953 {
  strings:
    $key_2953 = { 7d 3b [2] 09 23 [2] 4e 21 [2] 09 30 [2] 47 3c [2] 4b 36 [2] 5c 3d [2] 47 73 [2] 7a }

  condition:
    any of them
}