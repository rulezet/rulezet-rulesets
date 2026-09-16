rule TTP_XOR_WriteProcessMemory_e4cf {
  strings:
    $key_e4cf = { b3 bd [2] 81 9f [2] 87 aa [2] a9 aa [2] 96 b6 }

  condition:
    any of them
}