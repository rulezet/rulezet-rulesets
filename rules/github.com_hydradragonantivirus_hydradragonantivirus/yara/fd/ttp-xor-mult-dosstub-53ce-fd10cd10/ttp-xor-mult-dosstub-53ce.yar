rule TTP_XOR_MULT_DOSStub_53ce {
  strings:
    $key_53ce = { 07 a6 [2] 73 be [2] 34 bc [2] 73 ad [2] 3d a1 [2] 31 ab [2] 26 a0 [2] 3d ee [2] 00 }

  condition:
    any of them
}