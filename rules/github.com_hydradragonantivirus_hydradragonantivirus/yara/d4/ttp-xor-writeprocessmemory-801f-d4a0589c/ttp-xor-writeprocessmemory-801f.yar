rule TTP_XOR_WriteProcessMemory_801f {
  strings:
    $key_801f = { d7 6d [2] e5 4f [2] e3 7a [2] cd 7a [2] f2 66 }

  condition:
    any of them
}