rule TTP_XOR_WriteProcessMemory_5897 {
  strings:
    $key_5897 = { 0f e5 [2] 3d c7 [2] 3b f2 [2] 15 f2 [2] 2a ee }

  condition:
    any of them
}