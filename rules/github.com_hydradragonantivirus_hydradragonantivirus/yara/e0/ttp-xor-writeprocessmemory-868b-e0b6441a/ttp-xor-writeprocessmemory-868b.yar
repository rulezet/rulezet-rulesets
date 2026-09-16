rule TTP_XOR_WriteProcessMemory_868b {
  strings:
    $key_868b = { d1 f9 [2] e3 db [2] e5 ee [2] cb ee [2] f4 f2 }

  condition:
    any of them
}