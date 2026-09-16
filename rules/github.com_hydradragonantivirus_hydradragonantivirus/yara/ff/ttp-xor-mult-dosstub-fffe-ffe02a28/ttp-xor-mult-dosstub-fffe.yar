rule TTP_XOR_MULT_DOSStub_fffe {
  strings:
    $key_fffe = { ab 96 [2] df 8e [2] 98 8c [2] df 9d [2] 91 91 [2] 9d 9b [2] 8a 90 [2] 91 de [2] ac }

  condition:
    any of them
}