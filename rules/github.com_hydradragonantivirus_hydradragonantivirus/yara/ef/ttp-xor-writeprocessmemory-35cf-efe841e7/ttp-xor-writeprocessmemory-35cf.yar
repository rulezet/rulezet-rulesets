rule TTP_XOR_WriteProcessMemory_35cf {
  strings:
    $key_35cf = { 62 bd [2] 50 9f [2] 56 aa [2] 78 aa [2] 47 b6 }

  condition:
    any of them
}