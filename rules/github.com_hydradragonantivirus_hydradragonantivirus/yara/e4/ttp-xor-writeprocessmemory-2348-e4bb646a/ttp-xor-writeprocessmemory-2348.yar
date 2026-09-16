rule TTP_XOR_WriteProcessMemory_2348 {
  strings:
    $key_2348 = { 74 3a [2] 46 18 [2] 40 2d [2] 6e 2d [2] 51 31 }

  condition:
    any of them
}