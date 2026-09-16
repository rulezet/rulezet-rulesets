rule TTP_XOR_WriteProcessMemory_800a {
  strings:
    $key_800a = { d7 78 [2] e5 5a [2] e3 6f [2] cd 6f [2] f2 73 }

  condition:
    any of them
}