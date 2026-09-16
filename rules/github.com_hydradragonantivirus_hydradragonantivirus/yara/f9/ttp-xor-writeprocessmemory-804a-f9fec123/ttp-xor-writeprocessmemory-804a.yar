rule TTP_XOR_WriteProcessMemory_804a {
  strings:
    $key_804a = { d7 38 [2] e5 1a [2] e3 2f [2] cd 2f [2] f2 33 }

  condition:
    any of them
}