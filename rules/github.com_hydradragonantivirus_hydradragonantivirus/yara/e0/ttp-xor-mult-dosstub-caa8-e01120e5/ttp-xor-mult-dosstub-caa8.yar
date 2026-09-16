rule TTP_XOR_MULT_DOSStub_caa8 {
  strings:
    $key_caa8 = { 9e c0 [2] ea d8 [2] ad da [2] ea cb [2] a4 c7 [2] a8 cd [2] bf c6 [2] a4 88 [2] 99 }

  condition:
    any of them
}