rule TTP_XOR_WriteProcessMemory_e085 {
  strings:
    $key_e085 = { b7 f7 [2] 85 d5 [2] 83 e0 [2] ad e0 [2] 92 fc }

  condition:
    any of them
}