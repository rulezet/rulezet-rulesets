rule TTP_XOR_WriteProcessMemory_fdd4 {
  strings:
    $key_fdd4 = { aa a6 [2] 98 84 [2] 9e b1 [2] b0 b1 [2] 8f ad }

  condition:
    any of them
}