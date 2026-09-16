rule TTP_XOR_WriteProcessMemory_58bc {
  strings:
    $key_58bc = { 0f ce [2] 3d ec [2] 3b d9 [2] 15 d9 [2] 2a c5 }

  condition:
    any of them
}