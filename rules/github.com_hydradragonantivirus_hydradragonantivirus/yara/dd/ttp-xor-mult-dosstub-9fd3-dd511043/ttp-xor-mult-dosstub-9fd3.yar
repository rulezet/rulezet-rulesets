rule TTP_XOR_MULT_DOSStub_9fd3 {
  strings:
    $key_9fd3 = { cb bb [2] bf a3 [2] f8 a1 [2] bf b0 [2] f1 bc [2] fd b6 [2] ea bd [2] f1 f3 [2] cc }

  condition:
    any of them
}