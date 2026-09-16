rule TTP_XOR_MULT_DOSStub_131e {
  strings:
    $key_131e = { 47 76 [2] 33 6e [2] 74 6c [2] 33 7d [2] 7d 71 [2] 71 7b [2] 66 70 [2] 7d 3e [2] 40 }

  condition:
    any of them
}