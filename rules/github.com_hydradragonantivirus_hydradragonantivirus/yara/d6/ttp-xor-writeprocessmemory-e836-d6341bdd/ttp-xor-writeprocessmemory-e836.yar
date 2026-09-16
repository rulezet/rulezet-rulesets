rule TTP_XOR_WriteProcessMemory_e836 {
  strings:
    $key_e836 = { bf 44 [2] 8d 66 [2] 8b 53 [2] a5 53 [2] 9a 4f }

  condition:
    any of them
}