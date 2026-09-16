rule TTP_XOR_MULT_DOSStub_341e {
  strings:
    $key_341e = { 60 76 [2] 14 6e [2] 53 6c [2] 14 7d [2] 5a 71 [2] 56 7b [2] 41 70 [2] 5a 3e [2] 67 }

  condition:
    any of them
}