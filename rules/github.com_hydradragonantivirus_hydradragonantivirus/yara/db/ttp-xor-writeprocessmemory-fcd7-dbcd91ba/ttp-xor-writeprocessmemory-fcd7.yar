rule TTP_XOR_WriteProcessMemory_fcd7 {
  strings:
    $key_fcd7 = { ab a5 [2] 99 87 [2] 9f b2 [2] b1 b2 [2] 8e ae }

  condition:
    any of them
}