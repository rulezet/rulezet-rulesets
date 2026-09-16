rule TTP_XOR_WriteProcessMemory_2bb5 {
  strings:
    $key_2bb5 = { 7c c7 [2] 4e e5 [2] 48 d0 [2] 66 d0 [2] 59 cc }

  condition:
    any of them
}