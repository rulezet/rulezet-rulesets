rule TTP_XOR_WriteProcessMemory_fa01 {
  strings:
    $key_fa01 = { ad 73 [2] 9f 51 [2] 99 64 [2] b7 64 [2] 88 78 }

  condition:
    any of them
}