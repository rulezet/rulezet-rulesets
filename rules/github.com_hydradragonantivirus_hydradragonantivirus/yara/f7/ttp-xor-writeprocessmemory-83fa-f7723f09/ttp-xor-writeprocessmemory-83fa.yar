rule TTP_XOR_WriteProcessMemory_83fa {
  strings:
    $key_83fa = { d4 88 [2] e6 aa [2] e0 9f [2] ce 9f [2] f1 83 }

  condition:
    any of them
}