rule TTP_XOR_MULT_DOSStub_1dff {
  strings:
    $key_1dff = { 49 97 [2] 3d 8f [2] 7a 8d [2] 3d 9c [2] 73 90 [2] 7f 9a [2] 68 91 [2] 73 df [2] 4e }

  condition:
    any of them
}