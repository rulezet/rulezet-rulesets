rule TTP_XOR_WriteProcessMemory_1648 {
  strings:
    $key_1648 = { 41 3a [2] 73 18 [2] 75 2d [2] 5b 2d [2] 64 31 }

  condition:
    any of them
}