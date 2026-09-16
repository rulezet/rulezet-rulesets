rule TTP_XOR_WriteProcessMemory_b9ae {
  strings:
    $key_b9ae = { ee dc [2] dc fe [2] da cb [2] f4 cb [2] cb d7 }

  condition:
    any of them
}