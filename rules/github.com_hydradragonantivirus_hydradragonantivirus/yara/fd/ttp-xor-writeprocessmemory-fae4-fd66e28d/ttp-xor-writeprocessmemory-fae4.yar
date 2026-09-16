rule TTP_XOR_WriteProcessMemory_fae4 {
  strings:
    $key_fae4 = { ad 96 [2] 9f b4 [2] 99 81 [2] b7 81 [2] 88 9d }

  condition:
    any of them
}