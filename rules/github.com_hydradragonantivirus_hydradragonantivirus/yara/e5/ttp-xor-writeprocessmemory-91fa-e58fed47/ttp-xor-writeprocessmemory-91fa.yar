rule TTP_XOR_WriteProcessMemory_91fa {
  strings:
    $key_91fa = { c6 88 [2] f4 aa [2] f2 9f [2] dc 9f [2] e3 83 }

  condition:
    any of them
}