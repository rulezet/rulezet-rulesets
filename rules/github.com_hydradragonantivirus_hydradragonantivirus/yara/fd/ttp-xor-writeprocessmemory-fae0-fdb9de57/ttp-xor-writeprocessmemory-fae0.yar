rule TTP_XOR_WriteProcessMemory_fae0 {
  strings:
    $key_fae0 = { ad 92 [2] 9f b0 [2] 99 85 [2] b7 85 [2] 88 99 }

  condition:
    any of them
}