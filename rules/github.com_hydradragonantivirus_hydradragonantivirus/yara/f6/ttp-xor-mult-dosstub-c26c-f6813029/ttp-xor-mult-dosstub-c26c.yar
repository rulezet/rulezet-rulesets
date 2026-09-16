rule TTP_XOR_MULT_DOSStub_c26c {
  strings:
    $key_c26c = { 96 04 [2] e2 1c [2] a5 1e [2] e2 0f [2] ac 03 [2] a0 09 [2] b7 02 [2] ac 4c [2] 91 }

  condition:
    any of them
}