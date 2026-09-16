rule TTP_XOR_MULT_DOSStub_ccde {
  strings:
    $key_ccde = { 98 b6 [2] ec ae [2] ab ac [2] ec bd [2] a2 b1 [2] ae bb [2] b9 b0 [2] a2 fe [2] 9f }

  condition:
    any of them
}