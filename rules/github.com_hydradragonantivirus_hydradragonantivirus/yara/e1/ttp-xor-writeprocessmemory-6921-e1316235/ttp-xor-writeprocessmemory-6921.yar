rule TTP_XOR_WriteProcessMemory_6921 {
  strings:
    $key_6921 = { 3e 53 [2] 0c 71 [2] 0a 44 [2] 24 44 [2] 1b 58 }

  condition:
    any of them
}