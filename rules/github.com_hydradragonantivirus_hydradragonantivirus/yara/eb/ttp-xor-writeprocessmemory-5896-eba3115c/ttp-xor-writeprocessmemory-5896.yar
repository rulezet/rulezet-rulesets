rule TTP_XOR_WriteProcessMemory_5896 {
  strings:
    $key_5896 = { 0f e4 [2] 3d c6 [2] 3b f3 [2] 15 f3 [2] 2a ef }

  condition:
    any of them
}