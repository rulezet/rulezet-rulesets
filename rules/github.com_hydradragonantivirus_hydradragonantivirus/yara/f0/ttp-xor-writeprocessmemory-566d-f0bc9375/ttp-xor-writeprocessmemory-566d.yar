rule TTP_XOR_WriteProcessMemory_566d {
  strings:
    $key_566d = { 01 1f [2] 33 3d [2] 35 08 [2] 1b 08 [2] 24 14 }

  condition:
    any of them
}