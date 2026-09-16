rule TTP_XOR_WriteProcessMemory_0728 {
  strings:
    $key_0728 = { 50 5a [2] 62 78 [2] 64 4d [2] 4a 4d [2] 75 51 }

  condition:
    any of them
}