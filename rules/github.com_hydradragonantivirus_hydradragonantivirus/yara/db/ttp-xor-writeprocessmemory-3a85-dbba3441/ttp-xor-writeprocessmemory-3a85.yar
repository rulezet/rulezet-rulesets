rule TTP_XOR_WriteProcessMemory_3a85 {
  strings:
    $key_3a85 = { 6d f7 [2] 5f d5 [2] 59 e0 [2] 77 e0 [2] 48 fc }

  condition:
    any of them
}