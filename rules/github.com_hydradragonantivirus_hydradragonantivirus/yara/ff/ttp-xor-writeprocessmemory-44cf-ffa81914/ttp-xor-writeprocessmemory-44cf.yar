rule TTP_XOR_WriteProcessMemory_44cf {
  strings:
    $key_44cf = { 13 bd [2] 21 9f [2] 27 aa [2] 09 aa [2] 36 b6 }

  condition:
    any of them
}