rule TTP_XOR_WriteProcessMemory_e823 {
  strings:
    $key_e823 = { bf 51 [2] 8d 73 [2] 8b 46 [2] a5 46 [2] 9a 5a }

  condition:
    any of them
}