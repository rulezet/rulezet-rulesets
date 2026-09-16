rule TTP_XOR_WriteProcessMemory_2248 {
  strings:
    $key_2248 = { 75 3a [2] 47 18 [2] 41 2d [2] 6f 2d [2] 50 31 }

  condition:
    any of them
}