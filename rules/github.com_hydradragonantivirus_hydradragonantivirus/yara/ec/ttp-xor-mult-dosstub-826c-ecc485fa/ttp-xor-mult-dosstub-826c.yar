rule TTP_XOR_MULT_DOSStub_826c {
  strings:
    $key_826c = { d6 04 [2] a2 1c [2] e5 1e [2] a2 0f [2] ec 03 [2] e0 09 [2] f7 02 [2] ec 4c [2] d1 }

  condition:
    any of them
}