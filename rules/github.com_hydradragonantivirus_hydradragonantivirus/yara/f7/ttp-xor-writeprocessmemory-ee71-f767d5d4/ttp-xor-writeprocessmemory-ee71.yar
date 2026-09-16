rule TTP_XOR_WriteProcessMemory_ee71 {
  strings:
    $key_ee71 = { b9 03 [2] 8b 21 [2] 8d 14 [2] a3 14 [2] 9c 08 }

  condition:
    any of them
}