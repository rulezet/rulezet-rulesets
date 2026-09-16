rule TTP_XOR_WriteProcessMemory_4814 {
  strings:
    $key_4814 = { 1f 66 [2] 2d 44 [2] 2b 71 [2] 05 71 [2] 3a 6d }

  condition:
    any of them
}