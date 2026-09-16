rule TTP_XOR_WriteProcessMemory_faa6 {
  strings:
    $key_faa6 = { ad d4 [2] 9f f6 [2] 99 c3 [2] b7 c3 [2] 88 df }

  condition:
    any of them
}