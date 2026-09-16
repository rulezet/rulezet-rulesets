rule TTP_XOR_WriteProcessMemory_76cf {
  strings:
    $key_76cf = { 21 bd [2] 13 9f [2] 15 aa [2] 3b aa [2] 04 b6 }

  condition:
    any of them
}