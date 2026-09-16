rule TTP_XOR_MULT_DOSStub_3e1d {
  strings:
    $key_3e1d = { 6a 75 [2] 1e 6d [2] 59 6f [2] 1e 7e [2] 50 72 [2] 5c 78 [2] 4b 73 [2] 50 3d [2] 6d }

  condition:
    any of them
}