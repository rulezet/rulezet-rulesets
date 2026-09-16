rule TTP_XOR_WriteProcessMemory_20cf {
  strings:
    $key_20cf = { 77 bd [2] 45 9f [2] 43 aa [2] 6d aa [2] 52 b6 }

  condition:
    any of them
}