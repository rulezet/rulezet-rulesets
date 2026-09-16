rule TTP_XOR_WriteProcessMemory_596d {
  strings:
    $key_596d = { 0e 1f [2] 3c 3d [2] 3a 08 [2] 14 08 [2] 2b 14 }

  condition:
    any of them
}