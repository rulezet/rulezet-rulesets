rule TTP_XOR_WriteProcessMemory_73cf {
  strings:
    $key_73cf = { 24 bd [2] 16 9f [2] 10 aa [2] 3e aa [2] 01 b6 }

  condition:
    any of them
}