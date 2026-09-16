rule TTP_XOR_WriteProcessMemory_70cf {
  strings:
    $key_70cf = { 27 bd [2] 15 9f [2] 13 aa [2] 3d aa [2] 02 b6 }

  condition:
    any of them
}