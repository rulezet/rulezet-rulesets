rule TTP_XOR_WriteProcessMemory_e087 {
  strings:
    $key_e087 = { b7 f5 [2] 85 d7 [2] 83 e2 [2] ad e2 [2] 92 fe }

  condition:
    any of them
}