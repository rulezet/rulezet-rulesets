rule TTP_XOR_WriteProcessMemory_62d8 {
  strings:
    $key_62d8 = { 35 aa [2] 07 88 [2] 01 bd [2] 2f bd [2] 10 a1 }

  condition:
    any of them
}