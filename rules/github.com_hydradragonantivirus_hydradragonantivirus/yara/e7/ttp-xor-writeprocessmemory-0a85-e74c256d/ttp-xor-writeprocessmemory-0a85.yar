rule TTP_XOR_WriteProcessMemory_0a85 {
  strings:
    $key_0a85 = { 5d f7 [2] 6f d5 [2] 69 e0 [2] 47 e0 [2] 78 fc }

  condition:
    any of them
}