rule TTP_XOR_WriteProcessMemory_2249 {
  strings:
    $key_2249 = { 75 3b [2] 47 19 [2] 41 2c [2] 6f 2c [2] 50 30 }

  condition:
    any of them
}