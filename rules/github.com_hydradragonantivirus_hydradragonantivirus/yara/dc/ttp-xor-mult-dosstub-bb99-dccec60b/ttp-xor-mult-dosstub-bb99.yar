rule TTP_XOR_MULT_DOSStub_bb99 {
  strings:
    $key_bb99 = { ef f1 [2] 9b e9 [2] dc eb [2] 9b fa [2] d5 f6 [2] d9 fc [2] ce f7 [2] d5 b9 [2] e8 }

  condition:
    any of them
}