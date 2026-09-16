rule TTP_XOR_WriteProcessMemory_1894 {
  strings:
    $key_1894 = { 4f e6 [2] 7d c4 [2] 7b f1 [2] 55 f1 [2] 6a ed }

  condition:
    any of them
}