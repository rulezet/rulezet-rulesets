rule TTP_XOR_WriteProcessMemory_2b93 {
  strings:
    $key_2b93 = { 7c e1 [2] 4e c3 [2] 48 f6 [2] 66 f6 [2] 59 ea }

  condition:
    any of them
}