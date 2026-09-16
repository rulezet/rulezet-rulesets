rule TTP_XOR_WriteProcessMemory_a06d {
  strings:
    $key_a06d = { f7 1f [2] c5 3d [2] c3 08 [2] ed 08 [2] d2 14 }

  condition:
    any of them
}