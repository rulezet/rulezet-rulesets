rule TTP_XOR_WriteProcessMemory_3148 {
  strings:
    $key_3148 = { 66 3a [2] 54 18 [2] 52 2d [2] 7c 2d [2] 43 31 }

  condition:
    any of them
}