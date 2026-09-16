rule TTP_XOR_WriteProcessMemory_0ae8 {
  strings:
    $key_0ae8 = { 5d 9a [2] 6f b8 [2] 69 8d [2] 47 8d [2] 78 91 }

  condition:
    any of them
}