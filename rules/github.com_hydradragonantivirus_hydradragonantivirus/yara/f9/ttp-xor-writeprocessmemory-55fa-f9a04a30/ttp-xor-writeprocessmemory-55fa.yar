rule TTP_XOR_WriteProcessMemory_55fa {
  strings:
    $key_55fa = { 02 88 [2] 30 aa [2] 36 9f [2] 18 9f [2] 27 83 }

  condition:
    any of them
}