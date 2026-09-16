rule TTP_XOR_MULT_DOSStub_9f98 {
  strings:
    $key_9f98 = { cb f0 [2] bf e8 [2] f8 ea [2] bf fb [2] f1 f7 [2] fd fd [2] ea f6 [2] f1 b8 [2] cc }

  condition:
    any of them
}