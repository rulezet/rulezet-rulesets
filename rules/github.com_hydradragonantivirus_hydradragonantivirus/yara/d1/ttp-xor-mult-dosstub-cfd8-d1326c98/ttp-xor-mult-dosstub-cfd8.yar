rule TTP_XOR_MULT_DOSStub_cfd8 {
  strings:
    $key_cfd8 = { 9b b0 [2] ef a8 [2] a8 aa [2] ef bb [2] a1 b7 [2] ad bd [2] ba b6 [2] a1 f8 [2] 9c }

  condition:
    any of them
}