rule TTP_XOR_WriteProcessMemory_b993 {
  strings:
    $key_b993 = { ee e1 [2] dc c3 [2] da f6 [2] f4 f6 [2] cb ea }

  condition:
    any of them
}