rule TTP_XOR_WriteProcessMemory_50cf {
  strings:
    $key_50cf = { 07 bd [2] 35 9f [2] 33 aa [2] 1d aa [2] 22 b6 }

  condition:
    any of them
}