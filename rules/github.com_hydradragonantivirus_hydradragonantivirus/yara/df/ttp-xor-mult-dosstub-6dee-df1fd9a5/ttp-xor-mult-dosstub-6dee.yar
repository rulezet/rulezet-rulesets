rule TTP_XOR_MULT_DOSStub_6dee {
  strings:
    $key_6dee = { 39 86 [2] 4d 9e [2] 0a 9c [2] 4d 8d [2] 03 81 [2] 0f 8b [2] 18 80 [2] 03 ce [2] 3e }

  condition:
    any of them
}