rule TTP_XOR_WriteProcessMemory_7894 {
  strings:
    $key_7894 = { 2f e6 [2] 1d c4 [2] 1b f1 [2] 35 f1 [2] 0a ed }

  condition:
    any of them
}