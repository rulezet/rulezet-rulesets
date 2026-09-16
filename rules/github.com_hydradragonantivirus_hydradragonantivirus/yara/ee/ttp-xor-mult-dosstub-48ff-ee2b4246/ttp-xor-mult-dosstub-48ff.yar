rule TTP_XOR_MULT_DOSStub_48ff {
  strings:
    $key_48ff = { 1c 97 [2] 68 8f [2] 2f 8d [2] 68 9c [2] 26 90 [2] 2a 9a [2] 3d 91 [2] 26 df [2] 1b }

  condition:
    any of them
}