rule TTP_XOR_WriteProcessMemory_bbfa {
  strings:
    $key_bbfa = { ec 88 [2] de aa [2] d8 9f [2] f6 9f [2] c9 83 }

  condition:
    any of them
}