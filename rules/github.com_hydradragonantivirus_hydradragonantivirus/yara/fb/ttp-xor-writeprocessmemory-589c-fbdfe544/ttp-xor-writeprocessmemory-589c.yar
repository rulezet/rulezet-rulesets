rule TTP_XOR_WriteProcessMemory_589c {
  strings:
    $key_589c = { 0f ee [2] 3d cc [2] 3b f9 [2] 15 f9 [2] 2a e5 }

  condition:
    any of them
}