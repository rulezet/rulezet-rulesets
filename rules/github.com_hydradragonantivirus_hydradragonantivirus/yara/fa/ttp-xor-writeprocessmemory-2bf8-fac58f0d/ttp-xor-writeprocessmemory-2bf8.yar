rule TTP_XOR_WriteProcessMemory_2bf8 {
  strings:
    $key_2bf8 = { 7c 8a [2] 4e a8 [2] 48 9d [2] 66 9d [2] 59 81 }

  condition:
    any of them
}