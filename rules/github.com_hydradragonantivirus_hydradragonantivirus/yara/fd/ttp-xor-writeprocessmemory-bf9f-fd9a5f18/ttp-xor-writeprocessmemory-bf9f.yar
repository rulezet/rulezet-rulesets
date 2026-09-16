rule TTP_XOR_WriteProcessMemory_bf9f {
  strings:
    $key_bf9f = { e8 ed [2] da cf [2] dc fa [2] f2 fa [2] cd e6 }

  condition:
    any of them
}