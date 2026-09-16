rule TTP_XOR_MULT_DOSStub_fad8 {
  strings:
    $key_fad8 = { ae b0 [2] da a8 [2] 9d aa [2] da bb [2] 94 b7 [2] 98 bd [2] 8f b6 [2] 94 f8 [2] a9 }

  condition:
    any of them
}