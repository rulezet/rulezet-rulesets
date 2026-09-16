rule TTP_XOR_MULT_DOSStub_0dee {
  strings:
    $key_0dee = { 59 86 [2] 2d 9e [2] 6a 9c [2] 2d 8d [2] 63 81 [2] 6f 8b [2] 78 80 [2] 63 ce [2] 5e }

  condition:
    any of them
}