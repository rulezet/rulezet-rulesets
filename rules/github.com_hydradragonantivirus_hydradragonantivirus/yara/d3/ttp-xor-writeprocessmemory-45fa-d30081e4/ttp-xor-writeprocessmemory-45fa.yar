rule TTP_XOR_WriteProcessMemory_45fa {
  strings:
    $key_45fa = { 12 88 [2] 20 aa [2] 26 9f [2] 08 9f [2] 37 83 }

  condition:
    any of them
}