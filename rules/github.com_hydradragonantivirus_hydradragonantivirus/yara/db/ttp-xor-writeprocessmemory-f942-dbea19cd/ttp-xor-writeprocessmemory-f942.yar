rule TTP_XOR_WriteProcessMemory_f942 {
  strings:
    $key_f942 = { ae 30 [2] 9c 12 [2] 9a 27 [2] b4 27 [2] 8b 3b }

  condition:
    any of them
}