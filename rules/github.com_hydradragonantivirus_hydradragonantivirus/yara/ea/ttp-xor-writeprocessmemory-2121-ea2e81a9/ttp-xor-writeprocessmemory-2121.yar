rule TTP_XOR_WriteProcessMemory_2121 {
  strings:
    $key_2121 = { 76 53 [2] 44 71 [2] 42 44 [2] 6c 44 [2] 53 58 }

  condition:
    any of them
}