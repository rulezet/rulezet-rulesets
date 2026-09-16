rule TTP_XOR_WriteProcessMemory_326d {
  strings:
    $key_326d = { 65 1f [2] 57 3d [2] 51 08 [2] 7f 08 [2] 40 14 }

  condition:
    any of them
}