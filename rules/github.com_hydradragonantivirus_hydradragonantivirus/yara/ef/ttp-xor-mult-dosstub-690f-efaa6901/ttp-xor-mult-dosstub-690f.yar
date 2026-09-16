rule TTP_XOR_MULT_DOSStub_690f {
  strings:
    $key_690f = { 3d 67 [2] 49 7f [2] 0e 7d [2] 49 6c [2] 07 60 [2] 0b 6a [2] 1c 61 [2] 07 2f [2] 3a }

  condition:
    any of them
}