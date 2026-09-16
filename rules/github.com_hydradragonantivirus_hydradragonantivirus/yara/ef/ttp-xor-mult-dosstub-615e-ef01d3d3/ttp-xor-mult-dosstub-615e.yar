rule TTP_XOR_MULT_DOSStub_615e {
  strings:
    $key_615e = { 35 36 [2] 41 2e [2] 06 2c [2] 41 3d [2] 0f 31 [2] 03 3b [2] 14 30 [2] 0f 7e [2] 32 }

  condition:
    any of them
}