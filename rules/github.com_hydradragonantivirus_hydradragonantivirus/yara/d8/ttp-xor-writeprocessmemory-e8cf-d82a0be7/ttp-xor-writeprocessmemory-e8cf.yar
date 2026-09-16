rule TTP_XOR_WriteProcessMemory_e8cf {
  strings:
    $key_e8cf = { bf bd [2] 8d 9f [2] 8b aa [2] a5 aa [2] 9a b6 }

  condition:
    any of them
}