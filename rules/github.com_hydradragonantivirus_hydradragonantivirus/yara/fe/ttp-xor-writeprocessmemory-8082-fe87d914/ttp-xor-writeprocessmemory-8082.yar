rule TTP_XOR_WriteProcessMemory_8082 {
  strings:
    $key_8082 = { d7 f0 [2] e5 d2 [2] e3 e7 [2] cd e7 [2] f2 fb }

  condition:
    any of them
}