rule TTP_XOR_WriteProcessMemory_7e30 {
  strings:
    $key_7e30 = { 29 42 [2] 1b 60 [2] 1d 55 [2] 33 55 [2] 0c 49 }

  condition:
    any of them
}