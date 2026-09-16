rule TTP_XOR_MULT_DOSStub_533c {
  strings:
    $key_533c = { 07 54 [2] 73 4c [2] 34 4e [2] 73 5f [2] 3d 53 [2] 31 59 [2] 26 52 [2] 3d 1c [2] 00 }

  condition:
    any of them
}