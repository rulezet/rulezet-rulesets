rule TTP_XOR_WriteProcessMemory_0a18 {
  strings:
    $key_0a18 = { 5d 6a [2] 6f 48 [2] 69 7d [2] 47 7d [2] 78 61 }

  condition:
    any of them
}