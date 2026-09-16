rule TTP_XOR_WriteProcessMemory_acd1 {
  strings:
    $key_acd1 = { fb a3 [2] c9 81 [2] cf b4 [2] e1 b4 [2] de a8 }

  condition:
    any of them
}