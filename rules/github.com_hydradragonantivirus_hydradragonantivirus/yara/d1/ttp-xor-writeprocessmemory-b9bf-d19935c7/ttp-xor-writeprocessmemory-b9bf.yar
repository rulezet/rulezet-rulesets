rule TTP_XOR_WriteProcessMemory_b9bf {
  strings:
    $key_b9bf = { ee cd [2] dc ef [2] da da [2] f4 da [2] cb c6 }

  condition:
    any of them
}