rule TTP_XOR_WriteProcessMemory_3514 {
  strings:
    $key_3514 = { 62 66 [2] 50 44 [2] 56 71 [2] 78 71 [2] 47 6d }

  condition:
    any of them
}