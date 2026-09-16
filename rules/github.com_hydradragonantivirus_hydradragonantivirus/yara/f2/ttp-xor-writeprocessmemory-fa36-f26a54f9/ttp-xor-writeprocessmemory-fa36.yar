rule TTP_XOR_WriteProcessMemory_fa36 {
  strings:
    $key_fa36 = { ad 44 [2] 9f 66 [2] 99 53 [2] b7 53 [2] 88 4f }

  condition:
    any of them
}