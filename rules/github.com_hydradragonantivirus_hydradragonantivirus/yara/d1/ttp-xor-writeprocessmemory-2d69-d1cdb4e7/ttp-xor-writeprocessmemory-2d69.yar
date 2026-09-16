rule TTP_XOR_WriteProcessMemory_2d69 {
  strings:
    $key_2d69 = { 7a 1b [2] 48 39 [2] 4e 0c [2] 60 0c [2] 5f 10 }

  condition:
    any of them
}