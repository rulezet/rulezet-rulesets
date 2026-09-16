rule TTP_XOR_WriteProcessMemory_0f0d {
  strings:
    $key_0f0d = { 58 7f [2] 6a 5d [2] 6c 68 [2] 42 68 [2] 7d 74 }

  condition:
    any of them
}