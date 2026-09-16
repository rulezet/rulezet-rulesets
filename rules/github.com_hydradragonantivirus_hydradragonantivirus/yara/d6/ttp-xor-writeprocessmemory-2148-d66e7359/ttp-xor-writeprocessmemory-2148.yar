rule TTP_XOR_WriteProcessMemory_2148 {
  strings:
    $key_2148 = { 76 3a [2] 44 18 [2] 42 2d [2] 6c 2d [2] 53 31 }

  condition:
    any of them
}