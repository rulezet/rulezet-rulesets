rule TTP_XOR_WriteProcessMemory_d144 {
  strings:
    $key_d144 = { 86 36 [2] b4 14 [2] b2 21 [2] 9c 21 [2] a3 3d }

  condition:
    any of them
}