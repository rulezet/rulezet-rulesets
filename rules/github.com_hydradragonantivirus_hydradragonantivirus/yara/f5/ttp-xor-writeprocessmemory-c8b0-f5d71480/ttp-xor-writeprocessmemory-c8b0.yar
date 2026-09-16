rule TTP_XOR_WriteProcessMemory_c8b0 {
  strings:
    $key_c8b0 = { 9f c2 [2] ad e0 [2] ab d5 [2] 85 d5 [2] ba c9 }

  condition:
    any of them
}