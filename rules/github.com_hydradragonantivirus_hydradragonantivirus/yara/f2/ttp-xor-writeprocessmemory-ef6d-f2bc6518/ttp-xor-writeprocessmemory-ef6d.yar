rule TTP_XOR_WriteProcessMemory_ef6d {
  strings:
    $key_ef6d = { b8 1f [2] 8a 3d [2] 8c 08 [2] a2 08 [2] 9d 14 }

  condition:
    any of them
}