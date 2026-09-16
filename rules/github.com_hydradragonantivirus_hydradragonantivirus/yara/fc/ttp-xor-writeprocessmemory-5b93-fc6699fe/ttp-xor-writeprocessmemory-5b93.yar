rule TTP_XOR_WriteProcessMemory_5b93 {
  strings:
    $key_5b93 = { 0c e1 [2] 3e c3 [2] 38 f6 [2] 16 f6 [2] 29 ea }

  condition:
    any of them
}