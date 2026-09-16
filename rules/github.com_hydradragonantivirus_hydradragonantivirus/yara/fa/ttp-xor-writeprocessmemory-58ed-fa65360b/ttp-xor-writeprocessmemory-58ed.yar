rule TTP_XOR_WriteProcessMemory_58ed {
  strings:
    $key_58ed = { 0f 9f [2] 3d bd [2] 3b 88 [2] 15 88 [2] 2a 94 }

  condition:
    any of them
}