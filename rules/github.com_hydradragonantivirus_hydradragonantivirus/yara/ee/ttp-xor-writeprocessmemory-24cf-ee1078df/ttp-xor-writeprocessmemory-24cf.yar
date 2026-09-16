rule TTP_XOR_WriteProcessMemory_24cf {
  strings:
    $key_24cf = { 73 bd [2] 41 9f [2] 47 aa [2] 69 aa [2] 56 b6 }

  condition:
    any of them
}