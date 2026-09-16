rule TTP_XOR_WriteProcessMemory_fa47 {
  strings:
    $key_fa47 = { ad 35 [2] 9f 17 [2] 99 22 [2] b7 22 [2] 88 3e }

  condition:
    any of them
}