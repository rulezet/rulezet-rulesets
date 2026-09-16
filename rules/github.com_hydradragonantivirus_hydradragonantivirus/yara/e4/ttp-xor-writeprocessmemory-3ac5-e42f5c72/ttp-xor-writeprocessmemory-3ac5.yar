rule TTP_XOR_WriteProcessMemory_3ac5 {
  strings:
    $key_3ac5 = { 6d b7 [2] 5f 95 [2] 59 a0 [2] 77 a0 [2] 48 bc }

  condition:
    any of them
}