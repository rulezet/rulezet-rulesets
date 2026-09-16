rule TTP_XOR_WriteProcessMemory_92fa {
  strings:
    $key_92fa = { c5 88 [2] f7 aa [2] f1 9f [2] df 9f [2] e0 83 }

  condition:
    any of them
}