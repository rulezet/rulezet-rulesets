rule TTP_XOR_WriteProcessMemory_ac89 {
  strings:
    $key_ac89 = { fb fb [2] c9 d9 [2] cf ec [2] e1 ec [2] de f0 }

  condition:
    any of them
}