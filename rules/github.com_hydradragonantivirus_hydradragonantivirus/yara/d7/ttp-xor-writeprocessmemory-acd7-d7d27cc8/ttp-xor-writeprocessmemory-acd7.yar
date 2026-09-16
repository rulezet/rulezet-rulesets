rule TTP_XOR_WriteProcessMemory_acd7 {
  strings:
    $key_acd7 = { fb a5 [2] c9 87 [2] cf b2 [2] e1 b2 [2] de ae }

  condition:
    any of them
}