rule TTP_XOR_WriteProcessMemory_c993 {
  strings:
    $key_c993 = { 9e e1 [2] ac c3 [2] aa f6 [2] 84 f6 [2] bb ea }

  condition:
    any of them
}