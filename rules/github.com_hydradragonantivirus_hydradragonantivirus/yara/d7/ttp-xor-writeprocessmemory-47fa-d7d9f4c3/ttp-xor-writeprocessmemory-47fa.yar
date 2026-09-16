rule TTP_XOR_WriteProcessMemory_47fa {
  strings:
    $key_47fa = { 10 88 [2] 22 aa [2] 24 9f [2] 0a 9f [2] 35 83 }

  condition:
    any of them
}