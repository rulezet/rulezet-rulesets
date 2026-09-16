rule TTP_XOR_MULT_DOSStub_2f90 {
  strings:
    $key_2f90 = { 7b f8 [2] 0f e0 [2] 48 e2 [2] 0f f3 [2] 41 ff [2] 4d f5 [2] 5a fe [2] 41 b0 [2] 7c }

  condition:
    any of them
}