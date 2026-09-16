rule TTP_XOR_MULT_DOSStub_480e {
  strings:
    $key_480e = { 1c 66 [2] 68 7e [2] 2f 7c [2] 68 6d [2] 26 61 [2] 2a 6b [2] 3d 60 [2] 26 2e [2] 1b }

  condition:
    any of them
}