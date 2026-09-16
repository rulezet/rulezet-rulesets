rule TTP_XOR_MULT_DOSStub_921d {
  strings:
    $key_921d = { c6 75 [2] b2 6d [2] f5 6f [2] b2 7e [2] fc 72 [2] f0 78 [2] e7 73 [2] fc 3d [2] c1 }

  condition:
    any of them
}