rule TTP_XOR_WriteProcessMemory_e871 {
  strings:
    $key_e871 = { bf 03 [2] 8d 21 [2] 8b 14 [2] a5 14 [2] 9a 08 }

  condition:
    any of them
}