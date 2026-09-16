rule TTP_XOR_MULT_DOSStub_fd23 {
  strings:
    $key_fd23 = { a9 4b [2] dd 53 [2] 9a 51 [2] dd 40 [2] 93 4c [2] 9f 46 [2] 88 4d [2] 93 03 [2] ae }

  condition:
    any of them
}