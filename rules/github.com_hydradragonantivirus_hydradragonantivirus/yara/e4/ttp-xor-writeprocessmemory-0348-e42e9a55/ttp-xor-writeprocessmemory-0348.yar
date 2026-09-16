rule TTP_XOR_WriteProcessMemory_0348 {
  strings:
    $key_0348 = { 54 3a [2] 66 18 [2] 60 2d [2] 4e 2d [2] 71 31 }

  condition:
    any of them
}