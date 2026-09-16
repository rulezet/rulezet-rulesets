rule TTP_XOR_WriteProcessMemory_fb71 {
  strings:
    $key_fb71 = { ac 03 [2] 9e 21 [2] 98 14 [2] b6 14 [2] 89 08 }

  condition:
    any of them
}