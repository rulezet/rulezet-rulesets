rule TTP_XOR_WriteProcessMemory_806d {
  strings:
    $key_806d = { d7 1f [2] e5 3d [2] e3 08 [2] cd 08 [2] f2 14 }

  condition:
    any of them
}