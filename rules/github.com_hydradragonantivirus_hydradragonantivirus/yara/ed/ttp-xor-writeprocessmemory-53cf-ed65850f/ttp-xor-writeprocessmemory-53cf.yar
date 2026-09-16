rule TTP_XOR_WriteProcessMemory_53cf {
  strings:
    $key_53cf = { 04 bd [2] 36 9f [2] 30 aa [2] 1e aa [2] 21 b6 }

  condition:
    any of them
}