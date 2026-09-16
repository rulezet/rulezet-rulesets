rule TTP_XOR_WriteProcessMemory_bf9a {
  strings:
    $key_bf9a = { e8 e8 [2] da ca [2] dc ff [2] f2 ff [2] cd e3 }

  condition:
    any of them
}