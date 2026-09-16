rule TTP_XOR_WriteProcessMemory_6c14 {
  strings:
    $key_6c14 = { 3b 66 [2] 09 44 [2] 0f 71 [2] 21 71 [2] 1e 6d }

  condition:
    any of them
}