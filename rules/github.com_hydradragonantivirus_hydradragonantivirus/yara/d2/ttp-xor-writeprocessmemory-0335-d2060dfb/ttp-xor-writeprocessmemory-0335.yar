rule TTP_XOR_WriteProcessMemory_0335 {
  strings:
    $key_0335 = { 54 47 [2] 66 65 [2] 60 50 [2] 4e 50 [2] 71 4c }

  condition:
    any of them
}