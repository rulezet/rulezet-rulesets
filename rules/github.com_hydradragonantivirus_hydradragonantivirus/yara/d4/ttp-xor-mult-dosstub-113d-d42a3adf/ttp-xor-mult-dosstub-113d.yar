rule TTP_XOR_MULT_DOSStub_113d {
  strings:
    $key_113d = { 45 55 [2] 31 4d [2] 76 4f [2] 31 5e [2] 7f 52 [2] 73 58 [2] 64 53 [2] 7f 1d [2] 42 }

  condition:
    any of them
}