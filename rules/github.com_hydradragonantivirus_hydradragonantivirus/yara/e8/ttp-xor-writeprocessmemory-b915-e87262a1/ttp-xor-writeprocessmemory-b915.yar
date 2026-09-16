rule TTP_XOR_WriteProcessMemory_b915 {
  strings:
    $key_b915 = { ee 67 [2] dc 45 [2] da 70 [2] f4 70 [2] cb 6c }

  condition:
    any of them
}