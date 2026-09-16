rule TTP_XOR_WriteProcessMemory_5d93 {
  strings:
    $key_5d93 = { 0a e1 [2] 38 c3 [2] 3e f6 [2] 10 f6 [2] 2f ea }

  condition:
    any of them
}