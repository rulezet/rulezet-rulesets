rule TTP_XOR_WriteProcessMemory_e98d {
  strings:
    $key_e98d = { be ff [2] 8c dd [2] 8a e8 [2] a4 e8 [2] 9b f4 }

  condition:
    any of them
}