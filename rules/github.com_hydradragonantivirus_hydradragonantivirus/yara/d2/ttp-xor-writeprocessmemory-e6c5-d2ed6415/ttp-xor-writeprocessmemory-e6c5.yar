rule TTP_XOR_WriteProcessMemory_e6c5 {
  strings:
    $key_e6c5 = { b1 b7 [2] 83 95 [2] 85 a0 [2] ab a0 [2] 94 bc }

  condition:
    any of them
}