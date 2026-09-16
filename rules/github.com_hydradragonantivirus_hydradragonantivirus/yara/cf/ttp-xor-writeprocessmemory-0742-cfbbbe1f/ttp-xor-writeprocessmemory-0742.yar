rule TTP_XOR_WriteProcessMemory_0742 {
  strings:
    $key_0742 = { 50 30 [2] 62 12 [2] 64 27 [2] 4a 27 [2] 75 3b }

  condition:
    any of them
}