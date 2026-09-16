rule TTP_XOR_MULT_DOSStub_083d {
  strings:
    $key_083d = { 5c 55 [2] 28 4d [2] 6f 4f [2] 28 5e [2] 66 52 [2] 6a 58 [2] 7d 53 [2] 66 1d [2] 5b }

  condition:
    any of them
}