rule TTP_XOR_WriteProcessMemory_66cf {
  strings:
    $key_66cf = { 31 bd [2] 03 9f [2] 05 aa [2] 2b aa [2] 14 b6 }

  condition:
    any of them
}