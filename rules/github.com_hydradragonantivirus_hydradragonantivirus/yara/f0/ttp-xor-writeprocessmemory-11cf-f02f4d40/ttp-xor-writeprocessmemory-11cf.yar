rule TTP_XOR_WriteProcessMemory_11cf {
  strings:
    $key_11cf = { 46 bd [2] 74 9f [2] 72 aa [2] 5c aa [2] 63 b6 }

  condition:
    any of them
}