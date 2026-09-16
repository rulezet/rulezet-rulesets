rule TTP_XOR_WriteProcessMemory_3f18 {
  strings:
    $key_3f18 = { 68 6a [2] 5a 48 [2] 5c 7d [2] 72 7d [2] 4d 61 }

  condition:
    any of them
}