rule TTP_XOR_WriteProcessMemory_3c93 {
  strings:
    $key_3c93 = { 6b e1 [2] 59 c3 [2] 5f f6 [2] 71 f6 [2] 4e ea }

  condition:
    any of them
}