rule TTP_XOR_WriteProcessMemory_ee6d {
  strings:
    $key_ee6d = { b9 1f [2] 8b 3d [2] 8d 08 [2] a3 08 [2] 9c 14 }

  condition:
    any of them
}