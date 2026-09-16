rule TTP_XOR_WriteProcessMemory_62cf {
  strings:
    $key_62cf = { 35 bd [2] 07 9f [2] 01 aa [2] 2f aa [2] 10 b6 }

  condition:
    any of them
}