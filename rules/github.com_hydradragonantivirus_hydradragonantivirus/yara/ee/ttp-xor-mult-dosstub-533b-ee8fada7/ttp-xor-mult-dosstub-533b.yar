rule TTP_XOR_MULT_DOSStub_533b {
  strings:
    $key_533b = { 07 53 [2] 73 4b [2] 34 49 [2] 73 58 [2] 3d 54 [2] 31 5e [2] 26 55 [2] 3d 1b [2] 00 }

  condition:
    any of them
}