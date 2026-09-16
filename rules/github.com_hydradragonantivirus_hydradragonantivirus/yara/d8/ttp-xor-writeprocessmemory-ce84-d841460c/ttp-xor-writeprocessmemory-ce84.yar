rule TTP_XOR_WriteProcessMemory_ce84 {
  strings:
    $key_ce84 = { 99 f6 [2] ab d4 [2] ad e1 [2] 83 e1 [2] bc fd }

  condition:
    any of them
}