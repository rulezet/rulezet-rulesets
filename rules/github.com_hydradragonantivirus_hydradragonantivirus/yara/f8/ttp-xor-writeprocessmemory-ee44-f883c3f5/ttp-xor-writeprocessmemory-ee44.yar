rule TTP_XOR_WriteProcessMemory_ee44 {
  strings:
    $key_ee44 = { b9 36 [2] 8b 14 [2] 8d 21 [2] a3 21 [2] 9c 3d }

  condition:
    any of them
}