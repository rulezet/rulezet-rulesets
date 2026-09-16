rule TTP_XOR_MULT_DOSStub_9f99 {
  strings:
    $key_9f99 = { cb f1 [2] bf e9 [2] f8 eb [2] bf fa [2] f1 f6 [2] fd fc [2] ea f7 [2] f1 b9 [2] cc }

  condition:
    any of them
}