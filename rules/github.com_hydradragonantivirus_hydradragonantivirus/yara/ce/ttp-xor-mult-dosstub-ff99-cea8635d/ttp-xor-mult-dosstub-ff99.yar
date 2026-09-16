rule TTP_XOR_MULT_DOSStub_ff99 {
  strings:
    $key_ff99 = { ab f1 [2] df e9 [2] 98 eb [2] df fa [2] 91 f6 [2] 9d fc [2] 8a f7 [2] 91 b9 [2] ac }

  condition:
    any of them
}