rule TTP_XOR_WriteProcessMemory_9dfa {
  strings:
    $key_9dfa = { ca 88 [2] f8 aa [2] fe 9f [2] d0 9f [2] ef 83 }

  condition:
    any of them
}