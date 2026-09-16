rule TTP_XOR_WriteProcessMemory_38cf {
  strings:
    $key_38cf = { 6f bd [2] 5d 9f [2] 5b aa [2] 75 aa [2] 4a b6 }

  condition:
    any of them
}