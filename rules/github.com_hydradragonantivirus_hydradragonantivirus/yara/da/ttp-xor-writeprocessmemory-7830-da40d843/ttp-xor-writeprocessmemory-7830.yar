rule TTP_XOR_WriteProcessMemory_7830 {
  strings:
    $key_7830 = { 2f 42 [2] 1d 60 [2] 1b 55 [2] 35 55 [2] 0a 49 }

  condition:
    any of them
}