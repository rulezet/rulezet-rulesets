rule TTP_XOR_WriteProcessMemory_808d {
  strings:
    $key_808d = { d7 ff [2] e5 dd [2] e3 e8 [2] cd e8 [2] f2 f4 }

  condition:
    any of them
}