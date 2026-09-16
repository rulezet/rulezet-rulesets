rule TTP_XOR_WriteProcessMemory_01cf {
  strings:
    $key_01cf = { 56 bd [2] 64 9f [2] 62 aa [2] 4c aa [2] 73 b6 }

  condition:
    any of them
}