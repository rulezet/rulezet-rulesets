rule TTP_XOR_WriteProcessMemory_3bc5 {
  strings:
    $key_3bc5 = { 6c b7 [2] 5e 95 [2] 58 a0 [2] 76 a0 [2] 49 bc }

  condition:
    any of them
}