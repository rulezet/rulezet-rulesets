rule TTP_XOR_WriteProcessMemory_b98a {
  strings:
    $key_b98a = { ee f8 [2] dc da [2] da ef [2] f4 ef [2] cb f3 }

  condition:
    any of them
}