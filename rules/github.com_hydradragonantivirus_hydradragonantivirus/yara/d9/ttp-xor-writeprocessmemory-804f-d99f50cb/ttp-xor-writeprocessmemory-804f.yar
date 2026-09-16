rule TTP_XOR_WriteProcessMemory_804f {
  strings:
    $key_804f = { d7 3d [2] e5 1f [2] e3 2a [2] cd 2a [2] f2 36 }

  condition:
    any of them
}