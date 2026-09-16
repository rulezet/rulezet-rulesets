rule TTP_XOR_WriteProcessMemory_6948 {
  strings:
    $key_6948 = { 3e 3a [2] 0c 18 [2] 0a 2d [2] 24 2d [2] 1b 31 }

  condition:
    any of them
}