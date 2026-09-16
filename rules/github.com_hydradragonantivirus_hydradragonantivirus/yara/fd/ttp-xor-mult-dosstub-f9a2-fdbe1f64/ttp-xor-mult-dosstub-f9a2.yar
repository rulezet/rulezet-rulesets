rule TTP_XOR_MULT_DOSStub_f9a2 {
  strings:
    $key_f9a2 = { ad ca [2] d9 d2 [2] 9e d0 [2] d9 c1 [2] 97 cd [2] 9b c7 [2] 8c cc [2] 97 82 [2] aa }

  condition:
    any of them
}