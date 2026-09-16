rule TTP_XOR_MULT_DOSStub_dacc {
  strings:
    $key_dacc = { 8e a4 [2] fa bc [2] bd be [2] fa af [2] b4 a3 [2] b8 a9 [2] af a2 [2] b4 ec [2] 89 }

  condition:
    any of them
}