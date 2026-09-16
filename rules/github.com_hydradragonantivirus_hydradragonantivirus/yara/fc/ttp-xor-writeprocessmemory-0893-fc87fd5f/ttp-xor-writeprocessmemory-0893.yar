rule TTP_XOR_WriteProcessMemory_0893 {
  strings:
    $key_0893 = { 5f e1 [2] 6d c3 [2] 6b f6 [2] 45 f6 [2] 7a ea }

  condition:
    any of them
}