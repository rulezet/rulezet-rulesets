rule TTP_XOR_MULT_DOSStub_48fd {
  strings:
    $key_48fd = { 1c 95 [2] 68 8d [2] 2f 8f [2] 68 9e [2] 26 92 [2] 2a 98 [2] 3d 93 [2] 26 dd [2] 1b }

  condition:
    any of them
}