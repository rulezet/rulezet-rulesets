rule TTP_XOR_WriteProcessMemory_5885 {
  strings:
    $key_5885 = { 0f f7 [2] 3d d5 [2] 3b e0 [2] 15 e0 [2] 2a fc }

  condition:
    any of them
}