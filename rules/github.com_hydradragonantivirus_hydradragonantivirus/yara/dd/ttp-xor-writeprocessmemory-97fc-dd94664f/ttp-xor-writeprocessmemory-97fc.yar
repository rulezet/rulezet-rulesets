rule TTP_XOR_WriteProcessMemory_97fc {
  strings:
    $key_97fc = { c0 8e [2] f2 ac [2] f4 99 [2] da 99 [2] e5 85 }

  condition:
    any of them
}