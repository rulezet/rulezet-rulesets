rule TTP_XOR_WriteProcessMemory_0894 {
  strings:
    $key_0894 = { 5f e6 [2] 6d c4 [2] 6b f1 [2] 45 f1 [2] 7a ed }

  condition:
    any of them
}