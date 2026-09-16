rule TTP_XOR_WriteProcessMemory_108b {
  strings:
    $key_108b = { 47 f9 [2] 75 db [2] 73 ee [2] 5d ee [2] 62 f2 }

  condition:
    any of them
}