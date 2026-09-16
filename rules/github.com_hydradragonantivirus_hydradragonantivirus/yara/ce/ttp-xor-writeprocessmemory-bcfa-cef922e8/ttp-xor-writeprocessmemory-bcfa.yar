rule TTP_XOR_WriteProcessMemory_bcfa {
  strings:
    $key_bcfa = { eb 88 [2] d9 aa [2] df 9f [2] f1 9f [2] ce 83 }

  condition:
    any of them
}