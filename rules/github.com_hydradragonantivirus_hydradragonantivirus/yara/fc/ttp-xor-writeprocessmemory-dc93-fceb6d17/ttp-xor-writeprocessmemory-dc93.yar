rule TTP_XOR_WriteProcessMemory_dc93 {
  strings:
    $key_dc93 = { 8b e1 [2] b9 c3 [2] bf f6 [2] 91 f6 [2] ae ea }

  condition:
    any of them
}