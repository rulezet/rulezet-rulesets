rule TTP_XOR_WriteProcessMemory_80ca {
  strings:
    $key_80ca = { d7 b8 [2] e5 9a [2] e3 af [2] cd af [2] f2 b3 }

  condition:
    any of them
}